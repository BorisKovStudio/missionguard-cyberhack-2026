"""One fixed private lease Exec, authenticated TLS BEFORE Bearer or stdin.

Trusted OWNER input only, never an agent tool. On-chain certificate/hostUri
bindings must be independently verified by the operator; this client neither
mints JWTs nor claims that supplied metadata authenticates itself. No retry.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import time
import uuid
from urllib.parse import urlencode, urlsplit

ROOT=Path(__file__).resolve().parents[2]
HELPER='deploy/akash/verify_ghcr_public.py'
HELPER_HASH='230cc6aa609d0dce2db0c47512f6cee842d75333cfb0746927b4c752e1044806'
MAX_INPUT=262144
MAX_MESSAGE=262150
MAX_OUTPUT=65536
TOKEN=re.compile(r'[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,4096}\Z')
OPS=frozenset({'status','init','provision','configure','activate'})

class Stop(Exception):
    pass

def require(value):
    if not value: raise Stop('owner_exec_stopped')

class Deadline:
    def __init__(self): self.until=time.monotonic()+30
    def remaining(self):
        value=self.until-time.monotonic(); require(value>0); return value

def helper():
    path=ROOT/HELPER
    require(path.parent.resolve(strict=True)==path.parent)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try: raw=os.read(fd,1048577)
    finally: os.close(fd)
    require(len(raw)<=1048576 and hashlib.sha256(raw).hexdigest()==HELPER_HASH)
    spec=importlib.util.spec_from_file_location('_owner_tls_primitives',path)
    v=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),v.__dict__)
    return v

def validate_binding(value,*,now=None):
    base={'schema_version','operator_run_id','provider_uri','provider_address','dseq','gseq','oseq',
          'tls_mode','verified_at','binding_evidence_sha256'}
    certificate={'certificate_pem','certificate_sha256','certificate_serial'}
    require(type(value) is dict and value.get('tls_mode') in ('ca_dns','chain_certificate'))
    require(set(value)==base|(certificate if value['tls_mode']=='chain_certificate' else set()))
    require(value['schema_version']=='1.0' and str(uuid.UUID(value['operator_run_id']))==value['operator_run_id'])
    require(type(value['provider_address']) is str and re.fullmatch(r'akash1[a-z0-9]{20,80}',value['provider_address']))
    for key in ('dseq','gseq','oseq'):require(type(value[key]) is int and 1<=value[key]<=2**63-1)
    require(type(value['verified_at']) is int and 0<=(int(time.time() if now is None else now)-value['verified_at'])<=300)
    require(type(value['binding_evidence_sha256']) is str and re.fullmatch(r'[0-9a-f]{64}',value['binding_evidence_sha256']))
    uri=urlsplit(value['provider_uri'])
    require(uri.scheme=='https' and uri.username is None and uri.password is None and not uri.query and not uri.fragment)
    require(uri.path in ('','/') and type(uri.hostname) is str and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',uri.hostname))
    require(any(c.isalpha() for c in uri.hostname) and 1<=(uri.port or 443)<=65535)
    if value['tls_mode']=='chain_certificate':
        pem=value['certificate_pem'];require(type(pem) is str and len(pem)<=65536 and pem.count('BEGIN CERTIFICATE')==1)
        der=ssl.PEM_cert_to_DER_cert(pem)
        require(hashlib.sha256(der).hexdigest()==value['certificate_sha256'])
        require(type(value['certificate_serial']) is str and value['certificate_serial'].isdecimal() and 0<int(value['certificate_serial'])<2**256)
    return uri.hostname,uri.port or 443

def tls_context(binding,v):
    if binding['tls_mode']=='ca_dns': return v.tls_context()
    # Verified chain-record certificate is the explicit trust anchor, NOT TOFU.
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname=False;context.verify_mode=ssl.CERT_REQUIRED
    context.minimum_version=ssl.TLSVersion.TLSv1_2;context.keylog_filename=None
    context.options|=ssl.OP_NO_COMPRESSION
    context.load_verify_locations(cadata=binding['certificate_pem'])
    context.set_alpn_protocols(['http/1.1'])
    return context

def verify_peer(binding,secure):
    require(secure.selected_alpn_protocol() in (None,'http/1.1'))
    if binding['tls_mode']=='chain_certificate':
        require(hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()==binding['certificate_sha256'])
        cert=secure.getpeercert()
        names=[value for group in cert['subject'] for key,value in group if key=='commonName']
        require(names==[binding['provider_address']])
        require(int(cert['serialNumber'],16)==int(binding['certificate_serial']))
    validate_binding(binding)  # Recheck freshness on the SAME connection before auth.

def connect(binding,v,deadline):
    host,port=validate_binding(binding);v.HOST=host
    family,kind,protocol,address=v.resolve(deadline)
    require(address[1]==443)
    address=(address[0],port,*address[2:])
    plain=socket.socket(family,kind,protocol);secure=None
    try:
        plain.settimeout(min(10,deadline.remaining()));plain.connect(address)
        plain.settimeout(min(5,deadline.remaining()))
        secure=tls_context(binding,v).wrap_socket(plain,server_hostname=host)
        verify_peer(binding,secure)
        return secure
    except BaseException:
        if secure is not None:secure.close()
        plain.close();raise

def request_path(binding,*,command_kind='bootstrap'):
    query={'service':'executor','podIndex':'0','stdin':'1','tty':'0'}
    require(command_kind in ('bootstrap','preflight','human'))
    if command_kind in ('preflight','human'):
        if command_kind=='preflight':from deploy.akash.owner_preflight import REMOTE_SOURCE
        else:from deploy.akash.owner_human import REMOTE_SOURCE
        words=('python3','-B','-c',REMOTE_SOURCE)
    else: words=('python3','-B','-m','missionguard.bootstrap','remote')
    for index,word in enumerate(words):query['cmd'+str(index)]=word
    return '/lease/{dseq}/{gseq}/{oseq}/shell?'.format(**binding)+urlencode(query)

def upgrade(secure,binding,jwt,v,deadline,*,command_kind='bootstrap'):
    require(type(jwt) is str and len(jwt)<=8192 and TOKEN.fullmatch(jwt))
    host,port=validate_binding(binding)
    nonce=base64.b64encode(os.urandom(16)).decode('ascii')
    expected=base64.b64encode(hashlib.sha1((nonce+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')).digest()).decode('ascii')
    raw=('GET '+request_path(binding,command_kind=command_kind)+' HTTP/1.1\r\nHost: '+host+':'+str(port)+'\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+nonce+'\r\nAuthorization: Bearer '+jwt+'\r\n\r\n').encode('ascii')
    secure.settimeout(deadline.remaining());secure.sendall(raw)
    reader=v.Reader(secure,deadline);line=reader.line(2048)
    require(re.fullmatch(rb'HTTP/1\.1 101 [\x20-\x7e]{0,120}',line))
    headers={};used=len(line)+2
    while True:
        line=reader.line(16384-used);used+=len(line)+2
        if not line:break
        require(len(headers)<64 and b':' in line)
        key,value=line.split(b':',1);require(v.FIELD.fullmatch(key) and all(32<=c<=126 for c in value))
        key=key.decode('ascii').lower();require(key not in headers);headers[key]=value.strip().decode('ascii')
    require(headers.get('upgrade','').lower()=='websocket' and headers.get('connection','').lower()=='upgrade')
    require(headers.get('sec-websocket-accept')==expected)
    require(not set(headers)&{'sec-websocket-extensions','sec-websocket-protocol','location','content-length','transfer-encoding','www-authenticate'})
    return reader

def send_frame(secure,deadline,opcode,payload):
    require(type(payload) is bytes and len(payload)<=MAX_MESSAGE)
    size=len(payload);mask=os.urandom(4)
    head=bytes([0x80|opcode,0x80|size]) if size<126 else bytes([0x80|opcode,0xfe])+size.to_bytes(2,'big') if size<=65535 else bytes([0x80|opcode,0xff])+size.to_bytes(8,'big')
    masked=bytes(value^mask[index%4] for index,value in enumerate(payload))
    secure.settimeout(deadline.remaining());secure.sendall(head+mask+masked)

def receive_message(reader,secure,deadline,budget):
    data=bytearray();fragment=False
    while True:
        deadline.remaining();budget[0]+=1;require(budget[0]<=512)
        first,second=reader.exact(2);fin=bool(first&128);opcode=first&15
        require(first&112==0 and not second&128)
        length=second&127
        if length==126:length=int.from_bytes(reader.exact(2),'big');require(length>=126)
        elif length==127:length=int.from_bytes(reader.exact(8),'big');require(length>=65536)
        require(length<=MAX_MESSAGE);budget[1]+=length;require(budget[1]<=1048576)
        if opcode>=8:require(fin and length<=125)
        payload=reader.exact(length)
        if opcode==9:send_frame(secure,deadline,10,payload);continue
        if opcode==10:continue
        require(opcode in (0,2) and (opcode==0 if fragment else opcode==2))
        data.extend(payload);require(len(data)<=MAX_MESSAGE)
        if fin:return bytes(data)
        fragment=True

def safe_result(v,request,stdout):
    value=v.strict_json(stdout,MAX_OUTPUT)
    operation=request['operation']
    keys={'schema_version','operation','session_id','status'}
    keys|={'ledger_id'} if operation=='init' else {'ledger_id','config_sha256'} if operation=='configure' else {'expected_ledger_id','config_sha256'} if operation=='activate' else set()
    require(set(value)==keys and value['schema_version']=='1.0' and value['operation']==operation)
    require(type(value['session_id']) is str and str(uuid.UUID(value['session_id']))==value['session_id'])
    require(operation=='status' or value['session_id']==request['session_id'])
    require(value['status']==('waiting_or_activation_unknown' if operation=='status' else 'activation_requested_outcome_unknown' if operation=='activate' else 'complete'))
    for key in ('ledger_id','expected_ledger_id'):
        if key in value:require(type(value[key]) is str and str(uuid.UUID(value[key]))==value[key])
    if 'config_sha256' in value:require(type(value['config_sha256']) is str and re.fullmatch(r'[0-9a-f]{64}',value['config_sha256']))
    if operation=='configure':require(value['ledger_id']==request['payload']['expected_ledger_id'])
    if operation=='activate':require(value['expected_ledger_id']==request['payload']['expected_ledger_id'] and value['config_sha256']==request['payload']['config_sha256'])
    return value

def reserve(binding,request,raw):
    parent=ROOT/'deploy/akash/operator_state'
    if not parent.exists():parent.mkdir(mode=0o700)
    require(parent.resolve(strict=True)==parent)
    info=parent.stat();require(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700)
    identity=json.dumps(binding,sort_keys=True,separators=(',',':')).encode()
    name=hashlib.sha256((binding['operator_run_id']+'\0'+request['operation']).encode()).hexdigest()+'.json'
    fd=os.open(parent/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        data=json.dumps({'state':'consumed_no_retry','binding_sha256':hashlib.sha256(identity).hexdigest(),
                         'operation':request['operation'],'input_sha256':hashlib.sha256(raw).hexdigest()},sort_keys=True).encode()
        require(os.write(fd,data)==len(data));os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def validate_request(request):
    require(type(request) is dict and set(request)=={'schema_version','operation','session_id','payload'})
    require(request['schema_version']=='1.0' and request['operation'] in OPS and type(request['payload']) is dict)
    operation,payload=request['operation'],request['payload']
    if operation=='status':require(request['session_id'] is None and payload=={})
    else:require(type(request['session_id']) is str and str(uuid.UUID(request['session_id']))==request['session_id'])
    if operation=='init':require(payload=={})
    elif operation=='configure':
        require(set(payload)=={'expected_ledger_id','public_sni','public_host'})
        name=payload['public_sni'];require(type(name) is str and re.fullmatch(r'[A-Za-z0-9.-]{1,253}',name))
        require(type(payload['public_host']) is str and re.fullmatch(re.escape(name)+r':[0-9]{1,5}',payload['public_host']))
        require(1<=int(payload['public_host'].rsplit(':',1)[1])<=65535)
        require(str(uuid.UUID(payload['expected_ledger_id']))==payload['expected_ledger_id'])
    elif operation=='activate':
        require(set(payload)=={'expected_ledger_id','config_sha256'})
        require(str(uuid.UUID(payload['expected_ledger_id']))==payload['expected_ledger_id'])
        require(type(payload['config_sha256']) is str and re.fullmatch(r'[0-9a-f]{64}',payload['config_sha256']))
    elif operation=='provision':
        require(set(payload)=={'schema_version','auth_config','tls_cert_pem','tls_key_pem'} and payload['schema_version']=='1.0')
    return request

def execute(binding,jwt,request):
    v=helper();validate_binding(binding)
    validate_request(request)
    require(type(jwt) is str and len(jwt)<=8192 and TOKEN.fullmatch(jwt))
    raw=json.dumps(request,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8');require(0<len(raw)<=MAX_INPUT)
    reserve(binding,request,raw)
    deadline=Deadline();secure=None
    try:
        secure=connect(binding,v,deadline)
        reader=upgrade(secure,binding,jwt,v,deadline)
        send_frame(secure,deadline,2,bytes([104])+len(raw).to_bytes(4,'big')+raw)
        stdout=bytearray();stderr_bytes=0;budget=[0,0]
        while True:
            message=receive_message(reader,secure,deadline,budget);require(message)
            channel,payload=message[0],message[1:]
            if channel==100:stdout.extend(payload);require(len(stdout)<=MAX_OUTPUT)
            elif channel==101:stderr_bytes+=len(payload);require(stderr_bytes<=4096)
            elif channel==102:
                result=v.strict_json(payload,8192)
                require(set(result)<={'exit_code','message'} and type(result.get('exit_code')) is int and result['exit_code']==0 and result.get('message','')=='')
                output=safe_result(v,request,bytes(stdout))
                return {'status':'activation_unknown' if request['operation']=='activate' else 'remote_command_completed',
                        'remote_result':output,'stderr_bytes':stderr_bytes,'runtime_ready_verified':False,'retry':False}
            else:raise Stop('owner_exec_stopped')
    finally:
        if secure is not None:secure.close()

def main(argv=None):
    parser=argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--execute-reviewed',action='store_true')
    args=parser.parse_args(argv)
    if not args.execute_reviewed:parser.print_help();return 0
    try:
        # Reuse the existing bounded explicit frame reader, never EOF-based input.
        if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
        from missionguard.bootstrap import read_frame
        raw=read_frame(sys.stdin.buffer.fileno());v=helper();value=v.strict_json(raw,MAX_INPUT)
        require(set(value)=={'binding','jwt','request'})
        result=execute(value['binding'],value['jwt'],value['request'])
    except (Exception,KeyboardInterrupt):
        result={'status':'unknown_stop','retry':False,'runtime_ready_verified':False}
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
    return 0 if result['status']=='remote_command_completed' else 2

if __name__=='__main__':raise SystemExit(main())
