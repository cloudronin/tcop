"""Driver argument and serializer boundaries, with fake process/RPC clients."""
import json
import unittest
from copy import deepcopy
from tcop.cli_support import TCOPCommandError
from test_external_tightening_adapter import bound,candidate


class DriverTests(unittest.TestCase):
    def test_docker_pause_exact_id_no_shell(self):
        from tcop.external_binding_transports import DockerTransport
        from tcop.external_tightening_adapter import serialize_write
        calls=[]
        def run(argv):calls.append(argv);return ''
        t=DockerTransport(bound(),run=run,identity_reader=lambda:{})
        t.write(serialize_write(bound(),candidate('S-C','E2-extended-a')))
        self.assertEqual(calls,[['docker','pause','a'*64]])
    def test_snapshot_no_pause_and_no_restore(self):
        from tcop.external_binding_transports import DockerTransport
        from tcop.external_tightening_adapter import serialize_write
        c=dict(family='capability',row='capability',abstract_action='snapshot_sandbox',binding_id='snapshot',target='sandbox',sandbox_id='sandbox-B',generation='gen-1')
        calls=[]
        def run(argv):calls.append(argv);return 'sha256:'+'b'*64
        DockerTransport(bound(),run=run,identity_reader=lambda:{}).write(serialize_write(bound(),c,capability=True))
        self.assertEqual(calls,[['docker','commit','--no-pause','a'*64]])
    def test_docker_tampered_command_rejected_before_process(self):
        from tcop.external_binding_transports import DockerTransport
        from tcop.external_tightening_adapter import serialize_write
        calls=[];w=json.loads(serialize_write(bound(),candidate('S-C','E2-extended-a')));w['payload']['operation']='unpause'
        with self.assertRaises(TCOPCommandError):DockerTransport(bound(),run=lambda a:calls.append(a),identity_reader=lambda:{}).write(json.dumps(w).encode())
        self.assertEqual(calls,[])
    def test_native_rpc_only_merge_removal(self):
        from tcop.external_binding_transports import OpenShellTransport
        from tcop.external_tightening_adapter import serialize_write
        calls=[]
        def rpc(method,payload):calls.append((method,payload));return {'version':4,'policy_hash':'b'*64}
        OpenShellTransport(bound(),rpc,identity_reader=lambda:{}).write(serialize_write(bound(),candidate(row='E2-native-a')))
        writes=[v for v in calls if v[0]=='UpdateConfig'];self.assertEqual(len(writes),1);self.assertEqual(set(writes[0][1]['merge_operations'][0]),{'remove_endpoint'})
    def test_native_no_change_detected_from_unchanged_revision(self):
        from tcop.external_binding_transports import OpenShellTransport
        from tcop.external_tightening_adapter import serialize_write
        def rpc(method,payload):
            return {'revision':{'version':4,'policy_hash':'b'*64},'active_version':4} if method=='GetSandboxPolicyStatus' else {'version':4,'policy_hash':'b'*64}
        ack=OpenShellTransport(bound(),rpc,identity_reader=lambda:{}).write(serialize_write(bound(),candidate('S-A','E2-native-a')))
        self.assertTrue(ack['no_change'])
    def test_fingerprint_unavailable_after_detach_stays_persisted_not_rejected(self):
        from tcop.external_binding_transports import OpenShellTransport
        from tcop.external_tightening_adapter import serialize_write
        ack=OpenShellTransport(bound(),lambda m,p:{'detached':True},identity_reader=lambda:{}).write(serialize_write(bound(),candidate('S-C','E2-native-a')))
        self.assertTrue(ack['detached']);self.assertNotIn('provider_env_revision',ack)
    def test_native_detach_rejection_is_recorded(self):
        from tcop.external_binding_transports import OpenShellTransport,RPCRejected
        from tcop.external_tightening_adapter import serialize_write
        def rpc(method,payload):raise RPCRejected('FAILED_PRECONDITION')
        ack=OpenShellTransport(bound(),rpc,identity_reader=lambda:{}).write(serialize_write(bound(),candidate('S-C','E2-native-a')))
        self.assertTrue(ack['rejected'])
    def test_vm_client_can_only_add_bound_tuple(self):
        from tcop.external_binding_transports import VMWorkerTransport
        from tcop.external_tightening_adapter import serialize_write
        calls=[]
        def request(payload):calls.append(payload);return {'installed':True}
        t=VMWorkerTransport(bound(),request,identity_reader=lambda:{})
        t.write(serialize_write(bound(),candidate()));self.assertEqual(calls[0]['operation'],'add_bound_tuple')
        self.assertEqual(set(calls[0]),{'operation','tuple'})
    def test_vm_worker_rejects_arbitrary_target_at_boundary(self):
        from tcop.external_binding_transports import VMWorkerTransport
        from tcop.external_tightening_adapter import serialize_write
        calls=[];w=json.loads(serialize_write(bound(),candidate()));w['payload']['tuple']['destination_ip']='8.8.8.8'
        with self.assertRaises(TCOPCommandError):VMWorkerTransport(bound(),lambda p:calls.append(p),identity_reader=lambda:{}).write(json.dumps(w).encode())
        self.assertEqual(calls,[])
