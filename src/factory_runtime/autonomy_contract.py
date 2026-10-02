"""Load the exact owner-approved autonomy allowance without activating it."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

import jsonschema
import yaml

from factory_state.model import StateError

CONTRACT_PATH = Path('factory/autonomy/operating-contract.yaml')
SCHEMA_PATH = Path('factory/schemas/autonomy-operating-contract.schema.json')
COMMISSIONING_GATES = (
    'guarded_operational_role_activation',
    'live_controller_runtime_deployment',
    'guarded_schedule_activation',
)
COMMISSIONING_ID = 'factory-acceptance-commissioning-002'
ACCEPTANCE_CAPABILITY_ID = COMMISSIONING_ID
COMMISSIONING_EVIDENCE = 'factory/evidence/guarded-commissioning-002-authorization.json'


@dataclass(frozen=True)
class AutonomyOperatingAllowance:
    contract_id: str
    status: str
    provider_family: str
    model_id: str
    target_alias: str
    acceptance_repository: str
    acceptance_repository_id: int
    acceptance_contract_commit: str
    acceptance_contract_sha256: str
    acceptance_task_id: str
    acceptance_repository_ruleset_id: int
    acceptance_required_status_check: str
    maximum_total_cost: Decimal
    maximum_cost_per_call: Decimal
    maximum_provider_calls: int
    maximum_wall_clock_hours: int
    pricing_input_usd_per_million_tokens: Decimal
    pricing_output_usd_per_million_tokens: Decimal
    pricing_observed_at: datetime
    pricing_expires_at: datetime
    maximum_request_bytes_at_cost_cap: int
    pending_gates: tuple[str, ...]
    production_release_authorized: bool
    commissioning_starts_at: datetime | None = None
    commissioning_expires_at: datetime | None = None

    @property
    def activation_ready(self) -> bool:
        return self.status == 'ACTIVE' and not self.pending_gates

    def permits_activation(self, activation) -> bool:
        """Commissioning is one bounded exception, never proof of closed gates."""
        if self.activation_ready:
            return True
        from .autonomy import AutonomyActivation
        return (self.status == 'GUARDED_COMMISSIONING' and
            self.pending_gates == COMMISSIONING_GATES and
            self.commissioning_starts_at is not None and
            self.commissioning_expires_at is not None and
            isinstance(activation, AutonomyActivation) and
            activation.activation_id == COMMISSIONING_ID and
            activation.factory_id == 'tims-software-factory' and
            activation.task_id == self.acceptance_task_id and
            activation.contract_digest == 'sha256:' + self.acceptance_contract_sha256 and
            isinstance(activation.starts_at, datetime) and activation.starts_at.tzinfo is not None and
            isinstance(activation.expires_at, datetime) and activation.expires_at.tzinfo is not None and
            self.commissioning_starts_at <= activation.starts_at < activation.expires_at <=
            self.commissioning_expires_at)


def _commissioning_window(root, contract, pending):
    active = contract['status'] == 'GUARDED_COMMISSIONING'
    path = contract['approval'].get('commissioning_evidence')
    expected_authority = 'ALLOW_GUARDED_COMMISSIONING' if active else 'ALLOW_AFTER_ALL_GATES'
    if any(contract['authority'][key] != expected_authority for key in
           ('autonomous_task_progression', 'schedule_activation', 'provider_calls')):
        raise StateError('commissioning authority differs from contract status')
    if not active:
        if path is not None:
            raise StateError('commissioning evidence requires explicit commissioning status')
        return None, None
    if path != COMMISSIONING_EVIDENCE or pending != COMMISSIONING_GATES:
        raise StateError('commissioning must retain exactly the three unverified live gates')
    try:
        record = json.loads((root / path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise StateError('commissioning requires separate owner authorization evidence') from error
    expected = {
        'kind': 'guarded_commissioning_authorization', 'owner_identity': 'tim_brydges',
        'decision': 'AUTHORIZE_ONE_BOUNDED_COMMISSIONING_ACTIVATION',
        'activation_id': COMMISSIONING_ID, 'factory_id': 'tims-software-factory',
        'task_id': contract['acceptance_target']['task_id'],
        'contract_sha256': contract['acceptance_target']['contract_sha256'],
        'model_id': 'gpt-5.6-sol', 'currency': 'USD',
        'maximum_provider_calls': 3, 'maximum_cost_usd_per_call': '0.25',
        'maximum_reserved_cost_usd': '0.75', 'maximum_wall_clock_hours': 24,
        'maximum_remediation_cycles': 0, 'maximum_retries': 0,
        'pending_gates': list(COMMISSIONING_GATES), 'claims_live_gates_verified': False,
        'fresh_owner_and_reviewer_signatures_required': True,
        'immutable_source_job_and_role_pins_required': True,
        'production_release_authorized': False,
    }
    if (not isinstance(record, dict) or set(record) != set(expected) |
            {'authorization_text', 'authorized_at', 'expires_at'} or
            any(type(record.get(key)) is not type(value) or record[key] != value
                for key, value in expected.items()) or
            not isinstance(record['authorization_text'], str) or
            not record['authorization_text'].strip()):
        raise StateError('commissioning evidence differs from bounded owner approval')
    start = _pricing_time(record['authorized_at'], 'commissioning authorized_at')
    end = _pricing_time(record['expires_at'], 'commissioning expires_at')
    if not start < end <= start + timedelta(hours=24):
        raise StateError('commissioning authorization exceeds its time bound')
    return start, end


def _decimal(value, name):
    if not isinstance(value, str):
        raise StateError(f'{name} must be an exact decimal string')
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise StateError(f'{name} is invalid') from error
    if not parsed.is_finite() or parsed <= 0:
        raise StateError(f'{name} must be positive and finite')
    return parsed


def _pricing_time(value, name):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise StateError(f'{name} must be a UTC timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise StateError(f'{name} is invalid') from error
    if parsed.tzinfo != timezone.utc:
        raise StateError(f'{name} must be UTC')
    return parsed


def load_autonomy_operating_allowance(root: Path) -> AutonomyOperatingAllowance:
    try:
        contract = yaml.safe_load((root / CONTRACT_PATH).read_text(encoding='utf-8'))
        schema = json.loads((root / SCHEMA_PATH).read_text(encoding='utf-8'))
        jsonschema.Draft202012Validator(schema).validate(contract)
    except (OSError, ValueError, yaml.YAMLError, jsonschema.ValidationError) as error:
        raise StateError('autonomy operating contract is invalid') from error

    evidence_path = root / contract['approval']['evidence']
    try:
        evidence = json.loads(evidence_path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise StateError('autonomy financial authorization evidence is invalid') from error
    limits, provider = contract['limits'], contract['provider']
    expected = {
        'owner_identity': contract['approval']['owner_identity'],
        'authorized_on': contract['approval']['approved_on'],
        'provider_family': provider['family'], 'model_id': provider['model_id'],
        'target_alias': provider['target_alias'], 'currency': limits['currency'],
        'maximum_total_cost': limits['maximum_total_cost'],
        'maximum_cost_per_call': limits['maximum_cost_per_call'],
        'maximum_provider_calls': limits['maximum_provider_calls'],
        'maximum_automated_wall_clock_hours': limits['maximum_automated_wall_clock_hours'],
        'production_release_authorized': False,
    }
    if any(evidence.get(key) != value for key, value in expected.items()):
        raise StateError('autonomy contract differs from owner authorization evidence')
    target = contract['acceptance_target']
    try:
        target_evidence = json.loads(
            (root / target['evidence']).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise StateError('autonomy acceptance target evidence is invalid') from error
    target_expected = {
        'repository_full_name': target['repository_full_name'],
        'repository_id': target['repository_id'],
        'visibility': target['visibility'],
        'default_branch': target['default_branch'],
        'contract_path': target['contract_path'],
        'contract_commit': target['contract_commit'],
        'contract_blob_sha': target['contract_blob_sha'],
        'contract_sha256': target['contract_sha256'],
        'task_id': target['task_id'],
        'repository_ruleset_id': target['repository_ruleset_id'],
        'repository_ruleset_name': target['repository_ruleset_name'],
        'required_status_check': target['required_status_check'],
    }
    if any(target_evidence.get(key) != value for key, value in target_expected.items()):
        raise StateError('autonomy contract differs from acceptance target evidence')
    pricing = contract['pricing_reference']
    try:
        pricing_evidence = json.loads(
            (root / pricing['evidence']).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise StateError('autonomy pricing reference evidence is invalid') from error
    pricing_expected = {
        'model_id': pricing['model_id'],
        'processing_mode': pricing['processing_mode'],
        'context_class': pricing['context_class'],
        'long_context_threshold_input_tokens':
            pricing['long_context_threshold_input_tokens'],
        'input_usd_per_million_tokens':
            pricing['input_usd_per_million_tokens'],
        'output_usd_per_million_tokens':
            pricing['output_usd_per_million_tokens'],
        'observed_at': pricing['observed_at'],
        'expires_at': pricing['expires_at'],
        'conservative_maximum_cost_per_call':
            pricing['conservative_maximum_cost_per_call'],
    }
    if any(pricing_evidence.get(key) != value
           for key, value in pricing_expected.items()):
        raise StateError('autonomy contract differs from pricing reference evidence')
    pricing_observed_at = _pricing_time(pricing['observed_at'], 'pricing observed_at')
    pricing_expires_at = _pricing_time(pricing['expires_at'], 'pricing expires_at')
    if not pricing_observed_at < pricing_expires_at <= pricing_observed_at + timedelta(hours=24):
        raise StateError('autonomy pricing reference exceeds the 24-hour freshness window')
    input_price = _decimal(
        pricing['input_usd_per_million_tokens'], 'pricing input rate')
    output_price = _decimal(
        pricing['output_usd_per_million_tokens'], 'pricing output rate')
    conservative_cost = (
        Decimal(limits['maximum_request_bytes_at_cost_cap']) * input_price
        + Decimal(limits['maximum_output_tokens_per_call']) * output_price
    ) / Decimal(1_000_000)
    if conservative_cost != _decimal(
            pricing['conservative_maximum_cost_per_call'],
            'conservative maximum cost per call'):
        raise StateError('autonomy pricing cost bound is inconsistent')
    if conservative_cost > _decimal(
            limits['maximum_cost_per_call'], 'maximum cost per call'):
        raise StateError('autonomy pricing cost bound exceeds owner authorization')
    for gate in contract['activation']['verified_gates'].values():
        path = root / gate['evidence']
        if not path.is_file():
            raise StateError('verified autonomy gate evidence is missing')
    pending = tuple(contract['activation']['pending_gates'])
    exception = contract['activation']['verified_gates'].get('owner_review_requirement_exception')
    if exception is not None:
        try:
            record = json.loads((root / exception['evidence']).read_text(encoding='utf-8'))
        except (OSError, ValueError) as error:
            raise StateError('owner review exception evidence is invalid') from error
        if (record.get('kind') != 'owner_review_requirement_exception' or
                record.get('owner_identity') != contract['approval']['owner_identity'] or
                record.get('decision') != 'OWNER_EXCEPTION_NO_INDEPENDENT_REVIEW' or
                record.get('independent_review_performed') is not False or
                record.get('operational_activation_authorized_by_this_exception') is not False or
                record.get('model_calls_authorized_by_this_exception') != 0 or
                record.get('production_release_authorized') is not False or
                record.get('scope') != {
                    'repository': 'timbrydges/timscodefactory',
                    'acceptance_task': target['task_id'],
                    'candidate_pr': 198,
                    'waived_gate': 'independent_pre_activation_review'} or
                record.get('remaining_gates') != [
                    'approved_target_technical_enablement',
                    'guarded_operational_role_activation',
                    'live_controller_runtime_deployment',
                    'guarded_schedule_activation'] or
                'independent_pre_activation_review' in pending):
            raise StateError('owner review exception differs from bounded approval')
    if contract['status'] == 'ACTIVE' and pending:
        raise StateError('active autonomy contract retains pending gates')
    commissioning_start, commissioning_end = _commissioning_window(root, contract, pending)
    return AutonomyOperatingAllowance(contract['contract_id'], contract['status'], provider['family'],
        provider['model_id'], provider['target_alias'],
        target['repository_full_name'], target['repository_id'],
        target['contract_commit'], target['contract_sha256'], target['task_id'],
        target['repository_ruleset_id'], target['required_status_check'],
        _decimal(limits['maximum_total_cost'], 'maximum total cost'),
        _decimal(limits['maximum_cost_per_call'], 'maximum cost per call'),
        limits['maximum_provider_calls'], limits['maximum_automated_wall_clock_hours'],
        input_price, output_price, pricing_observed_at, pricing_expires_at,
        limits['maximum_request_bytes_at_cost_cap'],
        pending, contract['authority']['production_release'] != 'DENY',
        commissioning_start, commissioning_end)
