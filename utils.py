import datetime


def current_timestamp():
    return datetime.datetime.now().isoformat(timespec="seconds")


def safe_get(dictionary, key, default=""):
    value = dictionary.get(key)

    if value is None:
        return default

    return value