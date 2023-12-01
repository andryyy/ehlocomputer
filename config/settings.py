from enum import Enum


class SettingType(Enum):
    LDAP_CONNECTION = 1
    HTTP_CONNECTION = 2
    ATTR_ACTIVE = 3
    PLCY_ALLOW_EXT = 4
    PLCY_LIMIT_EXT_DESTS = 5
    CERT_CA = 6
    PLCY_OUT_RATELIMIT = 7
    PLCY_IN_RATELIMIT = 8
    AUTH_STATIC = 9
    AUTH_LDAP = 10
    AUTH_HTTP = 11


SETTINGS_DATA = {
    1: {
        "name": "LDAP Connection",
        "category": "🔌 Connection",
        "description": """
            Defines a LDAP connection.
        """,
        "source": ["ldap"],
        "required": [
            "ldap_uri",
            "ldap_base_dn",
            "ldap_bind_dn",
        ],
        "expected_value": [],
        "excluded": [
            "ldap_attribute",
        ],
    },
    2: {
        "name": "HTTP connection",
        "category": "🔌 Connection",
        "description": """
            Defines a HTTP connection.
        """,
        "source": ["http"],
        "required": [
            "http_url",
        ],
        "expected_value": [],
        "excluded": ["http_response"],
    },
    3: {
        "name": "Active",
        "category": "📝 Attribute",
        "description": """
            Indicates the active state of an assigned object.<br>
            When returning an integer, <b>1</b> is active, every other value indicates inactive.<br>
            A string or boolean "False" or "false" indicates inactive, <b>every other string</b> indicates active.
        """,
        "source": ["ldap", "http", "static"],
        "required": ["static_boolean", "ldap_attribute"],
        "expected_value": ["integer", "boolean", "string"],
        "excluded": [
            "static_number",
            "static_text",
            "ldap_uri",
            "ldap_search_scope",
            "ldap_base_dn",
            "ldap_bind_dn",
            "ldap_bind_passwd",
            "http_url",
            "http_status_code",
            "http_request_body",
            "http_request_header",
        ],
    },
    4: {
        "name": "External mailing",
        "category": "🧱 Policy",
        "description": """
            Allows the object to send mail outside its scope.<br>
            When returning an integer, <b>1</b> indicates permission to send, every other value indicates permits permission.
        """,
        "source": ["ldap", "http", "static"],
        "required": ["static_boolean", "ldap_filter", "ldap_attribute"],
        "expected_value": ["integer", "boolean"],
        "excluded": [],
    },
    5: {
        "name": "Limit external destinations",
        "category": "🧱 Policy",
        "description": """
            Limits outbound connections to specific targets.<br>
            A hostname target will match against <b>the hostname of the target's MX</b>.
            If you want to match email specific targets, a policy will fit your needs.
        """,
        "source": ["ldap", "http", "static"],
        "required": ["static_text", "ldap_filter", "ldap_attribute"],
        "expected_value": ["string", "string,string,..."],
        "excluded": [],
    },
    6: {
        "name": "CA certificate",
        "category": "🧾 Certificates",
        "description": """
            Define a CA to verify client connections with.
            Should contain a chain of certificates up to
            the client's certificate issuer.
        """,
        "source": ["static"],
        "required": [
            "text",
        ],
        "expected_value": ["text"],
        "excluded": ["static_boolean", "static_number"],
    },
    7: {
        "name": "Ratelimit outbound",
        "category": "🧱 Policy",
        "description": """
            Limit outbound mails per unit.<br>
            Unit can be days (d), hours (h), minutes (m), and seconds (s).<br>
            Example: <code>1/d</code>
        """,
        "source": ["ldap", "http", "static"],
        "required": ["static_text", "ldap_filter", "ldap_attribute"],
        "expected_value": ["number/unit"],
        "excluded": ["static_boolean", "static_number"],
    },
    8: {
        "name": "Ratelimit inbound",
        "category": "🧱 Policy",
        "description": """
            Limit inbound mails per unit.<br>
            Unit can be days (d), hours (h), minutes (m), and seconds (s).<br>
            Example: <code>1/d</code>
        """,
        "source": ["ldap", "http", "static"],
        "required": ["static_text", "ldap_filter", "ldap_attribute"],
        "expected_value": ["number/unit"],
        "excluded": [],
    },
    # {
    #     "id": 4,
    #     "name": "Inbound",
    #     "description": "Allows object to receive mail from outside its scope",
    #     "source": ["ldap", "http", "static"],
    #     "form": {}
    # },
    # {
    #     "id": 5,
    #     "name": "Limit inbound",
    #     "description": "Limits inbound connections to specific targets",
    #     "form": {}
    # },
    # {
    #     "id": 6,
    #     "name": "BCC",
    #     "description": "Send a Blind Carbon Copy (BCC) to a target",
    #     "form": {}
    # },
    # {
    #     "id": 7,
    #     "name": "Forward",
    #     "description": "Forward emails to a target",
    #     "form": {}
    # },
    # {
    #     "id": 8,
    #     "name": "Keep copy on forward",
    #     "description": "Forward a copy instead of redirecting the email",
    #     "form": {}
    # },
    # {
    #     "id": 9,
    #     "name": "Forward method",
    #     "description": "Forward server-side or after recieving. Forwarding an email after recieving it can be useful when email authentication (SPF, DKIM, etc.) is a problem.",
    #     "form": {}
    # },
    # {
    #     "id": 10,
    #     "name": "Allowed sender addresses",
    #     "description": "Additional addresses to be used as sender address.",
    #     "form": {}
    # },
    # {
    #     "id": 11,
    #     "name": "DKIM",
    #     "description": "Additional addresses to be used as sender address.",
    #     "form": {}
    # },
    # {
    #     "id": 12,
    #     "name": "Relayhost",
    #     "description": "Specifcy a relayhost to be used for outbound email.",
    #     "form": {}
    # },
    # {
    #     "id": 13,
    #     "name": "Relayhost filter",
    #     "description": "Define rules for when to use a relayhost.",
    #     "form": {}
    # },
    # {
    #     "id": 14,
    #     "name": "Credentials",
    #     "description": "Set credentials to be used in settings.",
    #     "form": {}
    # },
    # {
    #     "id": 15,
    #     "name": "Authentication backends",
    #     "description": "Define backends to authenticate against",
    #     "form": {}
    # },
    # {
    #     "id": 16,
    #     "name": "Fully trusted networks",
    #     "description": "Define trusted networks that always skip authentication.",
    #     "form": {}
    # },
    # {
    #     "id": 17,
    #     "name": "Username mapping",
    #     "description": "Define a username format.",
    #     "form": {}
    # },
    # {
    #     "id": 18,
    #     "name": "Require TFA token appended to password",
    #     "description": "When authenticating a TFA token is required to be appended to the password.",
    #     "form": {}
    # }
}
SETTINGS_CATEGORIES = set(x["category"] for x in SETTINGS_DATA.values())
