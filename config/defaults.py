from config.database import JSONStorage, RedisLockMiddleware

ACCEPT_LANGUAGES = ["en", "de"]
MAX_HISTORIC_REVISIONS = 5
WEBAUTHN_CHALLENGE_TIMEOUT = 30  # seconds
PROXY_AUTH_TIMEOUT = 300  # seconds
TABLE_PAGE_SIZE = 10
TINYDB = {
    "storage": RedisLockMiddleware(JSONStorage),
    "sort_keys": True,
    "indent": 2,
}
PODMAN_BINARY = "/usr/bin/podman"
TRUSTED_PROXIES = ["127.0.0.1", "::1"]
