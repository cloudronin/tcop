"""Unexecuted-on-CI OpenShell gRPC, Docker CLI and VM-worker drivers.

Every mutating entry point reconstructs and checks the closed wire again.
Read-only capture/journal inputs are separate from mutating transports.
"""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import socket
import subprocess
import time

from .cli_support import TCOPCommandError
from .external_foundation_seals import require, digest
from .external_tightening_adapter import validate_wire, validate_bound


class RPCRejected(Exception):
    """An explicit application rejection; not a network/timeout ambiguity."""


def run_argv(argv):
    r=subprocess.run(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=60)
    if r.returncode:raise OSError('external command failed; preserve its separate redacted acquisition log')
    return r.stdout


class CommonClock:
    def __init__(self,origin_unix_ms):
        require(type(origin_unix_ms) is int,'exact integer common-clock origin milliseconds required')
        self.origin_ns=origin_unix_ms*1000000
    def now_ms(self):return (time.time_ns()-self.origin_ns)/1000000
    def wait_until(self,at_ms):
        remaining=at_ms-self.now_ms()
        if remaining>0:time.sleep(remaining/1000)


class DockerIdentity:
    def __init__(self,bound,run=run_argv):self.bound=deepcopy(bound);self.run=run
    def __call__(self):
        b=self.bound;records=json.loads(self.run(['docker','inspect','--type','container',b['container_id']]))
        require(len(records)==1,'ambiguous container lookup');r=records[0];labels=r['Config'].get('Labels',{})
        require(r['Id']==b['container_id'] and labels.get('openshell.ai/managed-by')=='openshell'
            and labels.get('openshell.ai/sandbox-id')==b['sandbox_id'] and labels.get('openshell.ai/sandbox-name')==b['name'] and labels.get('openshell.ai/sandbox-workspace')==b['workspace'],'Docker identity/labels differ from admission')
        generation=digest({'id':r['Id'],'created':r['Created'],'started_at':r['State']['StartedAt'],'restart_count':r['RestartCount']})
        env=dict(v.split('=',1) for v in r['Config'].get('Env',[]) if '=' in v)
        poll=int(env.get('OPENSHELL_POLICY_POLL_INTERVAL_SECS','10'))
        require(b['container_ip'] in {n['IPAddress'] for n in r['NetworkSettings']['Networks'].values()},'container source IP changed')
        return {'sandbox_id':b['sandbox_id'],'container_id':r['Id'],'generation':generation,'poll_interval_secs':poll}


class Journal:
    """Receiver-owned capture, already mapped losslessly to the common clock.

    It must come from actual supervisor/proxy readbacks, not TCX contents.
    The journal is retained and hashed with the conformance/episode evidence.
    """
    def __init__(self,path):
        self.path=Path(path);self.seen=set()
        # Old refresh/status records must not establish a new action's effect.
        if self.path.exists():
            self.seen={digest(json.loads(line)) for line in self.path.read_text().splitlines()}
    def read(self):
        if not self.path.exists():return []
        found=[]
        for line in self.path.read_text().splitlines():
            event=json.loads(line);key=digest(event)
            if key not in self.seen:self.seen.add(key);found.append(event)
        return found


class _Transport:
    def __init__(self,bound,*,identity_reader,clock=None,journal=None):
        validate_bound(bound);self.bound=deepcopy(bound);self.identity_reader=identity_reader
        self.clock=clock;self.journal=journal
    def identity(self):return self.identity_reader()
    def _wire(self,wire):
        try:w=json.loads(wire)
        except ValueError as exc:raise TCOPCommandError('invalid serialized binding') from exc
        return validate_wire(self.bound,wire,capability=w.get('selection',{}).get('binding_id')=='snapshot')
    def _scoped(self,kind,**values):return {'kind':kind,**self.identity(),'at_ms':self.clock.now_ms(),**values}
    def _read_effect(self,w,ack):return []
    def observations(self,wire,ack,until_ms):
        w=self._wire(wire)
        require(self.clock is not None,'real observations require a common clock')
        while self.clock.now_ms()<=until_ms:
            events=self._read_effect(w,ack)
            if self.journal:events+=self.journal.read()
            for event in sorted(events,key=lambda e:e['at_ms']):yield event
            self.clock.wait_until(min(until_ms+1,self.clock.now_ms()+50))


class OpenShellTransport(_Transport):
    def __init__(self,bound,rpc,*,identity_reader,clock=None,journal=None,provider_fingerprint_reader=None):
        super().__init__(bound,identity_reader=identity_reader,clock=clock,journal=journal)
        self.rpc=rpc;self.provider_fingerprint_reader=provider_fingerprint_reader
    def write(self,wire):
        w=self._wire(wire);bid=w['selection']['binding_id']
        require(bid.startswith(('native-egress','provider-detach')),'non-native operation on native transport')
        method='UpdateConfig' if bid.startswith('native-egress') else 'DetachSandboxProvider'
        try:
            before=None
            if method=='UpdateConfig':
                before=self.rpc('GetSandboxPolicyStatus',{'name':self.bound['name'],'workspace':self.bound['workspace'],'version':0})
            response=self.rpc(method,w['payload'])
            if before:
                rev=before.get('revision',{})
                response['no_change']=bool(rev.get('version')==before.get('active_version',before.get('activeVersion'))==response.get('version') and rev.get('policy_hash',rev.get('policyHash'))==response.get('policy_hash') and response.get('policy_hash'))
            if self.clock:response['persisted_at_ms']=self.clock.now_ms()
            if method=='DetachSandboxProvider' and response.get('detached') is True:
                if self.provider_fingerprint_reader is not None:
                    try:
                        proof=self.provider_fingerprint_reader()
                        if proof.get('provider_absent') is True and proof.get('ambiguous') is False:
                            response['provider_env_revision']=proof['provider_env_revision']
                        else:response['fingerprint_readback']='ambiguous'
                    except (OSError,TimeoutError,KeyError):response['fingerprint_readback']='unavailable'
                else:response['fingerprint_readback']='unavailable'
            return response
        except RPCRejected as exc:return {'rejected':True,'reason':str(exc)}
    def _read_effect(self,w,ack):
        if not w['selection']['binding_id'].startswith('native-egress') or not ack.get('version'):return []
        raw=self.rpc('GetSandboxPolicyStatus',{'name':self.bound['name'],'workspace':self.bound['workspace'],'version':ack['version']})
        revision=raw.get('revision',{});status=revision.get('status')
        status={1:'PENDING',2:'LOADED',3:'FAILED',4:'SUPERSEDED'}.get(status,str(status).removeprefix('POLICY_STATUS_'))
        return [self._scoped('policy',status=status,version=revision.get('version'),active_version=raw.get('active_version',raw.get('activeVersion')),policy_hash=revision.get('policy_hash',revision.get('policyHash')))]


class DockerTransport(_Transport):
    def __init__(self,bound,*,run=run_argv,identity_reader,clock=None,journal=None):
        super().__init__(bound,identity_reader=identity_reader,clock=clock,journal=journal);self.run=run
    def write(self,wire):
        w=self._wire(wire);bid=w['selection']['binding_id'];require(bid in {'freeze','snapshot'},'non-Docker operation')
        argv=['docker','pause',self.bound['container_id']] if bid=='freeze' else ['docker','commit','--no-pause',self.bound['container_id']]
        output=self.run(argv).strip()
        return {'persisted_at_ms':self.clock.now_ms() if self.clock else None,'image_id':output if bid=='snapshot' else None}
    def _read_effect(self,w,ack):
        if w['selection']['binding_id']!='freeze':return []
        records=json.loads(self.run(['docker','inspect','--type','container',self.bound['container_id']]))
        require(len(records)==1 and records[0]['Id']==self.bound['container_id'],'freeze readback identity differs')
        return [self._scoped('paused',paused=records[0]['State']['Paused'])]


class VMWorkerTransport(_Transport):
    def __init__(self,bound,request,*,identity_reader,clock=None,journal=None):
        super().__init__(bound,identity_reader=identity_reader,clock=clock,journal=journal);self.request=request
    def write(self,wire):
        w=self._wire(wire);require(w['selection']['binding_id']=='instant-egress','VM worker only adds the bound deny tuple')
        return self.request(w['payload'])
    def _read_effect(self,w,ack):
        # This is a read, not another write to the set.
        expected=w['payload']['tuple'];r=self.request({'operation':'read_bound_tuple','tuple':expected})
        return [self._scoped('tuple',installed=r.get('installed') is True,tuple_matches=r.get('tuple')==expected)]


class UnixVMWorkerClient:
    """Connect only to the admitted deny-only worker's local forwarded socket."""
    def __init__(self,path):self.path=str(path)
    def __call__(self,payload):
        require(set(payload)=={'operation','tuple'} and payload['operation'] in {'add_bound_tuple','read_bound_tuple'},'worker operation forbidden')
        wire=json.dumps(payload,separators=(',',':')).encode()+b'\n'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(10);s.connect(self.path);s.sendall(wire);response=b''
            while b'\n' not in response:
                data=s.recv(4096);require(bool(data) and len(response)<65536,'invalid worker response');response+=data
        return json.loads(response.split(b'\n',1)[0])


def _run_grpc(argv):
    import re
    r=subprocess.run(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=60)
    if r.returncode:
        status=re.search(r'Code:\s*(InvalidArgument|PermissionDenied|Unauthenticated|FailedPrecondition|Aborted|NotFound|AlreadyExists|OutOfRange)',r.stderr)
        if status:raise RPCRejected(status.group(1))
        raise OSError('gRPC unavailable or indeterminate; preserve the separate redacted acquisition log')
    return r.stdout


class GRPCurl:
    """Pinned local gateway connection. No secret is accepted in argv/config."""
    def __init__(self,endpoint,proto_directory,*,run=_run_grpc):self.endpoint=endpoint;self.proto_directory=str(proto_directory);self.run=run
    def __call__(self,method,payload):
        require(method in {'UpdateConfig','DetachSandboxProvider','GetSandboxPolicyStatus'},'RPC outside binding surface')
        # Caller arranges an authenticated local gateway tunnel. Do not place a
        # bearer token in this command or in a saved config/fixture.
        argv=['grpcurl','-plaintext','-import-path',self.proto_directory,'-proto','openshell.proto','-d',json.dumps(payload),self.endpoint,'openshell.v1.OpenShell/'+method]
        response=json.loads(self.run(argv))
        # grpcurl normally uses JSON lowerCamelCase; normalize fields used by
        # the study while preserving the unmodified acquisition record outside.
        if 'policyHash' in response:response['policy_hash']=response.pop('policyHash')
        return response
