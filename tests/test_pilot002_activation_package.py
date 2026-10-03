import copy
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import test_pilot002_entrypoint as entry
import test_pilot002_runtime_package as runtime
from factory_state.scope import canonical
from factory_state.model import StateError

p=runtime.package


class ActivationPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.fixture=entry.EntrypointTests();self.fixture.setUp();self.fixture.setup_role()

    def files(self):
        return {**{name:(runtime.ROOT/name).read_bytes() for name in p.MATERIAL},
            'BUILD.json':canonical({'source_commit':'c'*40})}

    def validate(self,doc=None):
        files=self.files()
        result=p._activation(files,canonical(self.fixture.doc if doc is None else doc),self.fixture.fixtures.now)
        return result,files

    def test_all_three_roles_validate_without_clients_credentials_or_allowances(self):
        with patch('boto3.session.Session',side_effect=AssertionError('no cloud')),\
             patch('http.client.HTTPSConnection',side_effect=AssertionError('no provider')):
            for role in ('builder','inspector','qa'):
                self.fixture.setup_role(role)
                result,files=self.validate()
                self.assertEqual(result['role'],role)
                self.assertFalse(result['signed_allowance_included']);self.assertFalse(result['activation_authorized'])
                self.assertEqual(result['activation_sha256'],hashlib.sha256(files['PILOT002_ACTIVATION.json']).hexdigest())
                self.assertEqual(result['request_digest'],self.fixture.doc['qualification']['request_digest'])

    def test_mismatched_source_price_request_readiness_and_owner_rejected(self):
        mutations=(lambda d:d.update(source_commit='f'*40),
            lambda d:d['qualification'].update(request_digest='sha256:'+'0'*64),
            lambda d:d['qualification'].update(input_micro_usd_per_million=1000000000),
            lambda d:d['readiness'].update(request_digest='sha256:'+'0'*64),
            lambda d:d['readiness'].update(repository_binding_verified=False),
            lambda d:d['readiness'].update(extra='caller override'),
            lambda d:d['signer_registry']['signers'][0].update(revoked=True))
        for mutate in mutations:
            doc=copy.deepcopy(self.fixture.doc);mutate(doc)
            with self.subTest(doc=doc),self.assertRaises((ValueError,StateError)):self.validate(doc)

    def test_expired_readiness_and_qualification_rejected(self):
        for field in ('readiness','qualification'):
            doc=copy.deepcopy(self.fixture.doc);doc[field]['expires_at']=int(self.fixture.fixtures.now.timestamp())
            with self.subTest(field=field),self.assertRaises((ValueError,StateError)):self.validate(doc)

    def test_private_material_allowance_and_mutable_secret_routes_rejected(self):
        for change in ({'private_key':'never package me'},{'allowance':self.fixture.event['allowance']},
                       {'credential':{**self.fixture.doc['credential'],'version_id':'AWSCURRENT'}}):
            with self.subTest(change=change),self.assertRaises((ValueError,StateError)):self.validate({**self.fixture.doc,**change})

    def test_size_and_duplicate_keys_rejected(self):
        for raw in (b'',b'x'*131073,canonical(self.fixture.doc)[:-1]+b',"role":"qa"}'):
            with self.assertRaises((ValueError,StateError)):p._activation(self.files(),raw,self.fixture.fixtures.now)

    def build(self,output,activation):
        with patch.object(p.subprocess,'check_output',side_effect=['','c'*40]),\
             patch.object(p,'_blob',side_effect=lambda commit,name:(runtime.ROOT/name).read_bytes()),\
             patch.object(p,'_dependencies',return_value={'dependency/fixture.py':b'# synthetic'}):
            return p.build(output,activation=activation,now=self.fixture.fixtures.now)

    def test_activation_is_indexed_reproducible_and_still_probe_only(self):
        activation=self.root/'activation.json';activation.write_bytes(canonical(self.fixture.doc))
        one=self.root/'one.zip';two=self.root/'two.zip'
        result=self.build(one,activation);self.build(two,activation)
        self.assertEqual(one.read_bytes(),two.read_bytes())
        self.assertFalse(result['execution_enabled']);self.assertFalse(result['activation_authorized'])
        self.assertEqual(result['handler'],'factory_runtime.pilot002_runtime_probe.handler')
        with zipfile.ZipFile(one) as archive:
            raw=archive.read('PILOT002_ACTIVATION.json');index=json.loads(archive.read('PACKAGE.json'))
            self.assertEqual(raw,activation.read_bytes())
            self.assertEqual(index['files']['PILOT002_ACTIVATION.json'],result['activation_sha256'])
            self.assertEqual(set(archive.namelist()),set(index['files'])|{'PACKAGE.json'})

    def test_invalid_activation_leaves_no_deployable_archive(self):
        activation=self.root/'bad.json';activation.write_bytes(b'{}');output=self.root/'bad.zip'
        with self.assertRaises((ValueError,StateError)):self.build(output,activation)
        self.assertFalse(output.exists())


if __name__=='__main__':unittest.main()
