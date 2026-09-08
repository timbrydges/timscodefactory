def require_count(value):
    if not isinstance(value, int):
        raise TypeError("count must be integer")
    return value
