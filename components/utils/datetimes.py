import os
from datetime import datetime, timezone, UTC, timedelta


def system_now_as_str():
    return datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def ntime_utc_now():
    return datetime.now(UTC).timestamp()


def utc_now_as_str(dtformat="%Y-%m-%dT%H:%M:%S%z"):
    return datetime.now(timezone.utc).strftime(dtformat)


def last_modified_http(file):
    try:
        last_modified_time = os.path.getmtime(file)
    except FileNotFoundError:
        last_modified_time = 0
    return datetime.utcfromtimestamp(last_modified_time).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )


def parse_last_modified_http(last_modified_http):
    return datetime.strptime(last_modified_http, "%a, %d %b %Y %H:%M:%S GMT")
