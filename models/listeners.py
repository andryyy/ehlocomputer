import json
import os
import re
import uuid

from config import defaults
from config import lego
from config.database import *
from email_validator import validate_email
from pydantic import (
    AfterValidator,
    BaseModel,
    EmailStr,
    Field,
    FilePath,
    HttpUrl,
    field_validator,
    model_validator,
    validator,
)
from pydantic.networks import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal
from . import (
    utc_now_as_str,
    ensure_list,
    to_unique_sorted_str_list,
    get_validated_fqdn,
    flatten,
)


class ListenerCreate(BaseModel):
    id: Annotated[str, Field(default_factory=lambda: str(uuid.uuid4()))]
    name: Annotated[str, Field(min_length=1)]
    configuration: dict = {}
    historic: list = []
    created: Annotated[str, Field(default_factory=utc_now_as_str)]
    updated: Annotated[str, Field(default_factory=utc_now_as_str)]


class ListenerLegoConfig(BaseModel):
    lego_provider: str
    acme_terms_agreed: Literal[True, "true"]
    provider_config: dict
    acme_server: Annotated[str, AfterValidator(lambda x: str(HttpUrl(x)))]
    acme_email: EmailStr
    key_type: Literal["EC256", "EC384", "RSA2048", "RSA4096", "RSA8192"] = "RSA2048"
    domains: str

    @model_validator(mode="before")
    @classmethod
    def check_lego(self, data: Any) -> Any:
        if data.get("lego_provider") not in lego.LEGO_DNS_PROVIDERS.keys():
            raise ValueError(
                f"Value {data.get('lego_provider')} is not a lego provider"
            )

        _envs_available = flatten(
            [
                list(p.keys())
                for p in lego.LEGO_DNS_PROVIDERS.get(data.get("lego_provider"), [])
            ]
        )
        for _k, _v in data.get("provider_config").items():
            if _k not in _envs_available:
                raise ValueError(
                    f"{_k} is not a valid environment variable for the given lego DNS client"
                )
            if not isinstance(_v, str):
                raise ValueError(f"Value of {_k} is not a string")

        return data


class ListenerServerListener(BaseModel):
    hostname: Annotated[
        str,
        AfterValidator(lambda x: get_validated_fqdn(x)),
    ]

    config_assignment: str = "none"

    tls_method: Literal["lego_acme", "path", "unsafe"] | None = "unsafe"
    tls_cert_path: FilePath | None = None
    tls_key_path: FilePath | None = None

    smtp: bool | None = None
    smtp_proxy_protocol: bool | None = None
    smtp_tls_min_protocol: Literal[
        "TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"
    ] | None = "TLSv1_2"
    smtp_tls_ciphers: str = "HIGH:!aNULL:!MD5"

    smtps: bool | None = None
    smtps_proxy_protocol: bool | None = None
    smtps_tls_min_protocol: Literal[
        "TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"
    ] | None = "TLSv1_3"
    smtps_tls_ciphers: str = "HIGH:!aNULL:!MD5"

    submission: bool | None = None
    submission_proxy_protocol: bool | None = None
    submission_tls_min_protocol: Literal[
        "TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"
    ] | None = "TLSv1_3"
    submission_tls_ciphers: str = "HIGH:!aNULL:!MD5"

    imaps: bool | None = None
    imaps_proxy_protocol: bool | None = None
    imaps_tls_min_protocol: Literal[
        "TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"
    ] | None = "TLSv1_3"
    imaps_tls_ciphers: str = "HIGH:!aNULL:!MD5"

    smtp_ipv4_bind: Annotated[str, AfterValidator(lambda x: str(IPv4Address(x)))]
    smtps_ipv4_bind: Annotated[str, AfterValidator(lambda x: str(IPv4Address(x)))]
    submission_ipv4_bind: Annotated[str, AfterValidator(lambda x: str(IPv4Address(x)))]
    imaps_ipv4_bind: Annotated[str, AfterValidator(lambda x: str(IPv4Address(x)))]
    smtp_ipv4_port: int
    smtps_ipv4_port: int
    submission_ipv4_port: int
    imaps_ipv4_port: int

    smtp_ipv6_bind: Annotated[str, AfterValidator(lambda x: str(IPv6Address(x)))] | None
    smtps_ipv6_bind: Annotated[
        str, AfterValidator(lambda x: str(IPv6Address(x)))
    ] | None
    submission_ipv6_bind: Annotated[
        str, AfterValidator(lambda x: str(IPv6Address(x)))
    ] | None
    imaps_ipv6_bind: Annotated[
        str, AfterValidator(lambda x: str(IPv6Address(x)))
    ] | None
    smtp_ipv6_port: int | None
    smtps_ipv6_port: int | None
    submission_ipv6_port: int | None
    imaps_ipv6_port: int | None

    revision: Annotated[str, Field(default_factory=utc_now_as_str)]

    @model_validator(mode="before")
    @classmethod
    def listener_validation_before(cls, data: Any) -> Any:
        if (data["tls_cert_path"] == data["tls_cert_path"] == "") or data[
            "tls_method"
        ] != "path":
            data["tls_cert_path"] = data["tls_key_path"] = None
        return data

    @model_validator(mode="after")
    def listener_validation_after(cls, m: "ListenerServerListener"):
        _config = m.dict()
        for service in ["smtp", "submission", "smtps", "imaps"]:
            if _config.get(service) == True:
                if _config.get(f"{service}_ipv4_bind") == "0.0.0.0":
                    raise ValueError(
                        f"IPv4 binding for service {service.upper()} cannot equal an unspecific IP address (0.0.0.0)"
                    )
                if _config.get(f"{service}_ipv6_bind") == "::":
                    raise ValueError(
                        f"IPv6 binding for service {service.upper()} cannot equal an unspecific IP address (::)"
                    )
        return m


class ListenerPatch(BaseModel):
    id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))]
    name: Annotated[str, Field(min_length=1)]
    updated: Annotated[str, Field(default_factory=utc_now_as_str)]
    configuration: ListenerServerListener
    historic: list = []
