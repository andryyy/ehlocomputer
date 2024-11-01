import os
from pydantic import constr

ACCEPT_LANGUAGES = ["en", "de"]
WEBAUTHN_CHALLENGE_TIMEOUT = 30  # seconds
AUTH_REQUEST_TIMEOUT = 300  # seconds
TABLE_PAGE_SIZE = 20
TRUSTED_PROXIES = ["127.0.0.1", "::1"]
TEMPLATES_AUTO_RELOAD = True
SEND_FILE_MAX_AGE_DEFAULT = 31536000
USER_ACLS = ["user", "system"]
DISABLE_CACHE = False
LOG_LEVEL = "DEBUG"
LOG_FILE_RETENTION = 3
LOG_FILE_ROTATION = "3 days"
PRESERVE_SESSION_KEYS = []
ACCESS_TOKEN_FORMAT = constr(
    min_length=16,
)
UTCNOW_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
NODENAME = "debian-4gb-nbg1-2"
HYPERCORN_BIND = "162.55.49.111:443"
CLUSTER_PEERS_THEM = ["2.58.53.49", "37.27.93.56"]
CLUSTER_PEERS_ME = "162.55.49.111"
PREFERED_MASTER_PEER = "162.55.49.111"
HOSTNAME = "gyst.debinux.de"
WEBAUTHN_RP_NAME = "gyst"  # The human-readable RP name the server will report
WEBAUTHN_RP_ID = HOSTNAME  # Should be the effective domain
WEBAUTHN_RP_ORIGIN = HOSTNAME  # Origins the server will accept requests from
SECRET_KEY = os.getenv("SESSION_SECRET", "im-insecure")  # can be overridden by env var
TLS_CERTFILE = "system/certs/fullchain.pem"
TLS_KEYFILE = "system/certs/privkey.pem"
TLS_CA = "/etc/ssl/certs/ca-certificates.crt"
CLUSTER_CLI_BINDINGS = ["127.0.0.1", "::1"]
