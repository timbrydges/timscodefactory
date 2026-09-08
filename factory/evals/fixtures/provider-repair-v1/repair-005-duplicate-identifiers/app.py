def validate_ids(items):
    seen = set()
    for item in items:
        seen.add(item["id"])
    return True
