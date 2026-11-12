"""Owner-approved model list for development attempts (factory/models.json).

The stage caps are sized for US$4.00 input and US$20.00 output per million
tokens, so a listed model may cost no more than that. Unknown models, malformed
entries and prices above the ceiling fail closed.
"""
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re

MODELS = Path(__file__).resolve().parents[2]/'factory'/'models.json'
CEILING = {'input': Decimal('4.00'), 'output': Decimal('20.00')}
MODEL_ID = re.compile(r'[a-z0-9][a-z0-9.-]{0,63}')


def _price(value):
    try:
        price = Decimal(value)
    except (InvalidOperation, TypeError):
        raise ValueError('invalid approved model price') from None
    if not price.is_finite() or price <= 0:
        raise ValueError('invalid approved model price')
    return price


def load(path=MODELS):
    data = json.loads(Path(path).read_bytes())
    if type(data) is not dict:
        raise ValueError('approved models file required')
    models = data.get('models')
    if data.get('schema') != 1 or type(models) is not dict or not 1 <= len(models) <= 10:
        raise ValueError('approved models file required')
    approved = {}
    for model_id, entry in models.items():
        if not MODEL_ID.fullmatch(model_id) or type(entry) is not dict:
            raise ValueError('invalid approved model')
        prices = {kind: _price(entry.get(f'max_{kind}_usd_per_million_tokens')) for kind in CEILING}
        if any(prices[kind] > CEILING[kind] for kind in CEILING):
            raise ValueError('approved model costs more than the stage caps allow')
        approved[model_id] = prices
    if data.get('default') not in approved:
        raise ValueError('default model must be approved')
    return data['default'], approved


def resolve(spec, path=MODELS):
    """Model for a task contract and its maximum prices; fails closed."""
    default, approved = load(path)
    model_id = spec.get('model', default)
    if model_id not in approved:
        raise ValueError('task model is not in the approved model list')
    return model_id, approved[model_id]
