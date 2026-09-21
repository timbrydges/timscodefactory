"""Signature boundary tests, with real OpenSSL and no cloud dependency."""
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.scope_dispatch_canary import fixture_keys, sign
from factory_state.scope import SignedScopeStore
from factory_state.model import StateError
from test_dispatch_ledger import snapshot, REQUEST, NOW

class Writes:
 def __init__(self): self.calls=[]
 def put_item(self,**request): self.calls.append(request)

class SignedScopeTests(unittest.TestCase):
 def setUp(self):
  self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
  keys,self.private=fixture_keys(self.directory.name)
  self.db=Writes();self.store=SignedScopeStore('table',self.db,keys)
  self.payload={'kind':'capability','factory_id':'factory','objective_id':REQUEST.objective_id,
   'capability_id':REQUEST.capability_id,'contract_digest':REQUEST.contract_digest,'owner_identity':'tim_brydges',
   'required_evidence':'Exact Factory acceptance test','stop_condition':'Stop when verified',
   'issued_at':int(NOW.timestamp()),'expires_at':int(NOW.timestamp())+300}
 def signed(self,payload=None,identity='tim_brydges'):
  return sign(payload or self.payload,self.private[identity],self.directory.name)
 def approve(self,payload=None,signature=None):
  return self.store.approve_capability(snapshot(),REQUEST,payload or self.payload,signature or self.signed(),now=NOW)
 def test_valid_owner_signature_writes_once_conditionally(self):
  self.approve();self.assertEqual(len(self.db.calls),1)
  self.assertEqual(self.db.calls[0]['ConditionExpression'],'attribute_not_exists(PK) AND attribute_not_exists(SK)')
  self.assertIn('approval_evidence_digest',self.db.calls[0]['Item'])
 def test_tampered_message_and_wrong_signer_cannot_write(self):
  with self.assertRaises(StateError): self.approve({**self.payload,'stop_condition':'changed'})
  with self.assertRaises(StateError): self.approve(signature=self.signed(identity='independent_inspector_service'))
  self.assertEqual(self.db.calls,[])
 def test_expired_unknown_fields_and_other_objective_cannot_write(self):
  for patch in ({'expires_at':int(NOW.timestamp())},{'extra':True},{'objective_id':'other'}):
   p={**self.payload,**patch}
   with self.assertRaises(StateError):self.approve(p,self.signed(p))
  self.assertEqual(self.db.calls,[])
 def test_job_supplied_approval_flag_cannot_replace_signature(self):
  with self.assertRaises(StateError):self.approve(signature=b'approved')
  self.assertEqual(self.db.calls,[])
