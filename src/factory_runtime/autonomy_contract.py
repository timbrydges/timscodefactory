"""Load the exact owner-approved autonomy allowance without activating it."""
from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

import jsonschema
import yaml

from factory_state.model import StateError

CONTRACT_PATH = Path('factory/autonomy/operating-contract.yaml')
SCHEMA_PATH = Path('factory/schemas/autonomy-operating-contract.schema.json')


@dataclass(frozen=True)
class AutonomyOperatingAllowance:
    contract_id: str
    provider_family: str
    model_id: str
    target_alias: str
    maximum_total_cost: Decimal
    maximum_cost_per_call: Decimal
    maximum_provider_calls: int
    maximum_wall_clock_hours: int
    pending_gates: tuple[str, ...]
    production_release_authorized: bool

    @property
    def activation_ready(self) -> bool:
        return not self.pending_gates


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
    for gate in contract['activation']['verified_gates'].values():
        path = root / gate['evidence']
        if not path.is_file():
            raise StateError('verified autonomy gate evidence is missing')
    pending = tuple(contract['activation']['pending_gates'])
    if contract['status'] == 'ACTIVE' and pending:
        raise StateError('active autonomy contract retains pending gates')
    return AutonomyOperatingAllowance(contract['contract_id'], provider['family'],
        provider['model_id'], provider['target_alias'],
        _decimal(limits['maximum_total_cost'], 'maximum total cost'),
        _decimal(limits['maximum_cost_per_call'], 'maximum cost per call'),
        limits['maximum_provider_calls'], limits['maximum_automated_wall_clock_hours'],
        pending, contract['authority']['production_release'] != 'DENY')
