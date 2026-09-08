import json

def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
