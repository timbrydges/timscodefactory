"""Read immutable deployment files, never event-supplied security authority."""
import json
from dataclasses import dataclass

from factory_state.dispatch import DispatchRequest
from factory_state.model import StateError
from factory_state.scope import canonical
from .pilot002_entrypoint import _read, _pairs
from .review_verdict import ReviewBinding
from .security_material import PinnedSecurityMaterial
from .worker import digest


@dataclass(frozen=True)
class SecurityDeployment:
    material: PinnedSecurityMaterial
    qa_binding: ReviewBinding
    qa_request: DispatchRequest


def load_deployment(root, env, *, clock):
    """Pins must originate in the authenticated deployer, not arbitrary uploads.

    QA bytes identify historical evidence only. ConsumedQAProvenance must still
    authenticate its retained signature and current consumed-evidence record.
    This loader performs no cloud calls, signing, activation or credential reads.
    """
    try:
        build=json.loads(_read(root,'BUILD.json',1024),object_pairs_hook=_pairs)
        if type(build) is not dict or set(build)!={'source_commit'}:
            raise StateError('Exact security build source required')
        raw=_read(root,'SECURITY_QA.json',8192)
        if digest(raw)!=env.get('FACTORY_SECURITY_QA_DIGEST'):
            raise StateError('Historical QA deployment pin differs')
        doc=json.loads(raw,object_pairs_hook=_pairs)
        if (type(doc) is not dict or canonical(doc)!=raw or
                set(doc)!={'kind','qa_binding','qa_request','qa_result_digest'} or
                doc['kind']!='bounded_security004_qa_provenance' or
                type(doc['qa_binding']) is not dict or
                set(doc['qa_binding'])!=set(ReviewBinding.__dataclass_fields__) or
                type(doc['qa_binding']['allowed_paths']) is not list or
                type(doc['qa_request']) is not dict or
                set(doc['qa_request'])!=set(DispatchRequest.__dataclass_fields__)):
            raise StateError('Exact historical QA deployment configuration required')
        q=ReviewBinding(**{**doc['qa_binding'],'allowed_paths':tuple(doc['qa_binding']['allowed_paths'])})
        q.validate();request=DispatchRequest(**doc['qa_request'])
        if (request.source_commit,request.contract_digest,request.input_digest)!=(
                q.source_commit,q.contract_digest,q.input_digest):
            raise StateError('Historical QA request differs from binding')
        material=PinnedSecurityMaterial.load(_read(root,'REVIEW_MATERIAL.json',196608),
            expected_digest=env.get('FACTORY_SECURITY_MATERIAL_DIGEST'),
            deployed_commit=build['source_commit'],qa_binding=q,
            qa_result_digest=doc['qa_result_digest'],clock=clock)
        return SecurityDeployment(material,q,request)
    except (ValueError,TypeError,KeyError,AttributeError,RecursionError):
        raise StateError('Invalid security deployment configuration') from None
