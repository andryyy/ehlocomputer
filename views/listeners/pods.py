import json
import os
import requests
import time
import trustme

from . import tools as listeners_helpers
from ..configs import tools as configs_helpers
from base64 import b64encode
from config import defaults, logger
from config.database import *
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from datetime import datetime
from pathlib import Path
from podman import PodmanClient
from pydantic import validate_call
from ssl import SSLContext
from typing import Literal
from utils import helpers
from uuid import uuid4


class Listener:
    @validate_call
    def __init__(self, listener_id: str, realm_data: dict):
        self.realm_data = realm_data

        listener_by_id = listeners_helpers.get_listener_by_id(
            listener_id=listener_id, realm_path=self.realm_data["path"]
        )

        if not listener_by_id:
            raise ValueError("Listener ID does not exist")
        if not listener_by_id["configuration"].get("hostname"):
            raise ValueError("Listener ID does not provide a hostname")

        self.listener_id = listener_id
        self.podman_uri = f"unix://{self.realm_data['podman_socket']}"
        self.hostname = listener_by_id["configuration"].get("hostname")
        self.config = listener_by_id["configuration"]

        self.listener_volume_path = Path(f"{os.getcwd()}/volumes/{self.listener_id}")
        self.listener_volume_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.listener_volume = self.listener_volume_path.__str__()

        (self.listener_volume_path / "main.config").write_text(str(self.config))

    def __generate_service_ports_configuration__(self):
        # Set pod<>host port mappings
        container_service_ports = {
            "smtp": 10025,
            "submission": 10587,
            "smtps": 10465,
            "imaps": 10993,
        }

        self.services = [
            k
            for k, v in self.config.items()
            if v == True and k in ["smtp", "smtps", "submission", "imaps"]
        ]

        _portmappings = {}
        for service in self.services:
            ipv4_bind = self.config.get(f"{service}_ipv4_bind")
            ipv6_bind = self.config.get(f"{service}_ipv6_bind")

            _portmappings.update(
                {
                    f"{container_service_ports[service]}/tcp": [
                        (ipv4_bind, self.config.get(f"{service}_ipv4_port")),
                        (ipv6_bind, self.config.get(f"{service}_ipv6_port")),
                    ]
                }
            )

        self.smtpd_ports = _portmappings

    def __generate_self_signed_certificate__(self):
        if (
            not (self.listener_volume_path / "unsafe.crt").exists()
            or not (self.listener_volume_path / "unsafe_ca.crt").exists()
            or not (self.listener_volume_path / "unsafe.key").exists()
        ):
            ca = trustme.CA()
            ca.cert_pem.write_to_path(
                (self.listener_volume_path / "unsafe_ca.crt").as_posix()
            )
            server_cert = ca.issue_cert(
                f"*.{self.hostname}", self.hostname, key_type=trustme.KeyType(0)
            )
            key_descriptor = os.open(
                path=f"{self.listener_volume}/unsafe.key",
                flags=(os.O_WRONLY | os.O_CREAT | os.O_TRUNC),
                mode=0o600,
            )

            with open(f"{self.listener_volume}/unsafe.crt", "w+") as c:
                c.writelines(
                    "".join(
                        [c.bytes().decode("utf-8") for c in server_cert.cert_chain_pems]
                    )
                )

            with open(key_descriptor, "w+") as c:
                c.writelines(server_cert.private_key_pem.bytes().decode("utf-8"))

    def __generate_objects_configuration__(self):
        # List for configurations to apply to listener
        configurations = []

        # Definitions of domains, recipients
        self.running_config = {"domains": {}, "recipients": {}}

        if self.config.get("config_assignment") not in ["auto-assign", "none"]:
            configurations = [
                configs_helpers.get_config_by_id(
                    config_id=self.config.get("config_assignment"),
                    realm_path=self.realm_data["path"],
                )
            ]
        elif self.config.get("config_assignment") == "auto-assign":
            configurations = configs_helpers.get_config_by_suffix(
                suffix=self.hostname, realm_path=self.realm_data["path"]
            )

            if not [c["name"] for c in configurations if c["name"] == self.hostname]:
                raise ValueError(
                    "A dynamic configuration requires a configuration name matching the hostname"
                )

        for cfg in configurations:
            match_hostname = "__any__"

            if self.config.get("config_assignment") == "auto-assign":
                if cfg["name"] != self.hostname:
                    match_hostname = cfg["name"]

            translated_configuration = configs_helpers.translate_raw_config(
                raw_config=cfg["configuration"]["raw_config"],
                realm_path=self.realm_data["path"],
            )

            for domain in translated_configuration:
                domain_name = translated_configuration[domain]["data_object"][
                    "objectName"
                ]
                self.running_config["domains"][match_hostname] = {
                    domain_name: {
                        "settings": {},
                    },
                }

                for setting in translated_configuration[domain].get("settings", []):
                    for _, meta in setting.items():
                        self.running_config["domains"][match_hostname][domain_name][
                            "settings"
                        ].update(meta["data_object"]["objectData"])

                for recipient in translated_configuration[domain].get("recipients", []):
                    for _, meta in recipient.items():
                        full_recipient = (
                            meta["data_object"]["objectName"] + "@" + domain_name
                        )
                        self.running_config["recipients"][match_hostname] = {
                            full_recipient: {
                                "settings": self.running_config["domains"][
                                    match_hostname
                                ][domain_name]["settings"],
                            }
                        }

                        for setting in meta["settings"]:
                            for _, meta in setting.items():
                                self.running_config["recipients"][match_hostname][
                                    full_recipient
                                ]["settings"].update(meta["data_object"]["objectData"])

    def validate_certificate(self, nocache=False):
        global r
        revocation = {"CRL": {}, "OCSP": {}}
        chain = []
        # Read certificate from configured location
        try:
            if self.config["tls_method"] == "path":
                cert_path = self.listener_volume_path / "user.crt"
            elif self.config["tls_method"] == "lego_acme":
                cert_path = (
                    self.listener_volume_path / f"certificates/{self.hostname}.crt"
                )
            elif self.config["tls_method"] == "unsafe":
                cert_path = self.listener_volume_path / "unsafe.crt"
        except Exception as e:
            logger.error(e)
            return {}

        # cryptography 39 can use load_pem_x509_certificates
        with cert_path.open() as c:
            cert = ""
            for line in c:
                cert += line
                if "-----END CERTIFICATE-----" in line:
                    chain.append(x509.load_pem_x509_certificate(cert.encode("ascii")))
                    cert = ""

        # Collecting basic server_cert information
        server_cert = chain[0]
        subject_alternative_names = []
        cert_san_data = server_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        subject_alternative_names.extend(
            cert_san_data.value.get_values_for_type(x509.DNSName)
        )
        subject_alternative_names.extend(
            [
                i._string_from_ip_int(i._ip)
                for i in cert_san_data.value.get_values_for_type(x509.IPAddress)
            ]
        )
        not_valid_after_days = (server_cert.not_valid_after - datetime.utcnow()).days
        chain_subjects = [c.subject.rfc4514_string() for c in chain]

        if nocache == False and r.get(server_cert.serial_number):
            return json.loads(r.get(server_cert.serial_number))

        while chain:
            match chain:
                case [cert, issuer, *other]:
                    pass
                case [cert]:
                    issuer = None
            chain.pop(0)

            for e in cert.extensions:
                # Read OCSP URIs
                if isinstance(e.value, x509.AuthorityInformationAccess):
                    for x in e.value:
                        if (
                            issuer
                            and isinstance(x, x509.AccessDescription)
                            and x.access_method._name == "OCSP"
                        ):
                            revocation["OCSP"][cert.subject.rfc4514_string()] = {}
                            revocation["OCSP"][cert.subject.rfc4514_string()].update(
                                {
                                    "status": "failed",
                                }
                            )
                            req_build = (
                                ocsp.OCSPRequestBuilder()
                                .add_certificate(cert, issuer, hashes.SHA1())
                                .build()
                            )
                            req_path = b64encode(
                                req_build.public_bytes(serialization.Encoding.DER)
                            )

                            ocsp_req = requests.get(
                                f"{x.access_location.value}/{req_path.decode('ascii')}",
                                timeout=1,
                            )
                            revocation["OCSP"][cert.subject.rfc4514_string()].update(
                                {
                                    "ocsp_request_status_code": ocsp_req.status_code,
                                }
                            )

                            if ocsp_req.ok:
                                response = ocsp.load_der_ocsp_response(ocsp_req.content)
                                ocsp_response = response.certificate_status
                                if ocsp_response == ocsp.OCSPCertStatus.GOOD:
                                    revocation["OCSP"][
                                        cert.subject.rfc4514_string()
                                    ].update(
                                        {
                                            "status": "valid",
                                        }
                                    )
                                else:
                                    revocation["OCSP"][
                                        cert.subject.rfc4514_string()
                                    ].update(
                                        {
                                            "status": ocsp_response,
                                        }
                                    )
                # Read CRLs
                elif isinstance(e.value, x509.CRLDistributionPoints):
                    for x in e.value:
                        if isinstance(x, x509.DistributionPoint):
                            for uri in x.full_name:
                                revocation["CRL"][cert.subject.rfc4514_string()] = {}
                                revocation["CRL"][cert.subject.rfc4514_string()].update(
                                    {
                                        "status": "failed",
                                    }
                                )
                                crl_req = requests.get(uri.value, timeout=3)

                                revocation["CRL"][cert.subject.rfc4514_string()].update(
                                    {
                                        "crl_request_status_code": crl_req.status_code,
                                    }
                                )

                                if crl_req.ok:
                                    crl = None
                                    try:
                                        crl = x509.load_der_x509_crl(crl_req.content)
                                    except ValueError:
                                        crl = x509.load_pem_x509_crl(crl_req.content)

                                    if crl != None:
                                        revocation["CRL"][
                                            cert.subject.rfc4514_string()
                                        ].update(
                                            {
                                                "crl": crl_req.content.hex(),
                                            }
                                        )

                                        rvk_crt = crl.get_revoked_certificate_by_serial_number(
                                            cert.serial_number
                                        )
                                        if rvk_crt:
                                            revocation["CRL"][
                                                cert.subject.rfc4514_string()
                                            ].update(
                                                {
                                                    "status": "revoked",
                                                    "revoked_on": rvk_crt.revocation_date.strftime(
                                                        "%Y-%m-%dT%H:%M:%SZ"
                                                    ),
                                                }
                                            )
                                        else:
                                            revocation["CRL"][
                                                cert.subject.rfc4514_string()
                                            ].update({"status": "valid"})

        r.set(
            server_cert.serial_number,
            json.dumps(
                {
                    "not_valid_after_days": not_valid_after_days,
                    "revocation": revocation,
                    "cert_chain": chain_subjects,
                    "subject_alternative_names": subject_alternative_names,
                }
            ),
            ex=14400,
        )

        return json.loads(r.get(server_cert.serial_number))

    @validate_call
    def acquire_certificate(
        self, lego_config: dict, command: Literal["run", "renew"]
    ) -> None:
        with PodmanClient(base_url=self.podman_uri) as client:
            if client.containers.exists(f"{self.listener_id[:8]}-tls"):
                c = client.containers.get(f"{self.listener_id[:8]}-tls")
                if c.status != "exited":
                    c.stop()
                c.remove()

            c = client.containers.create(
                image="docker.io/goacme/lego",
                detach=True,
                labels={
                    "listener_id": self.listener_id,
                    "worker": "tls",
                    "io.containers.autoupdate": "registry",
                },
                mounts=[
                    {
                        "type": "bind",
                        "source": self.listener_volume,
                        "target": "/data",
                        "read_only": False,
                    }
                ],
                network_mode="pasta",
                command=[
                    "--server",
                    lego_config["acme_server"],
                    "--key-type",
                    lego_config["key_type"],
                    "--domains",
                    lego_config["domains"],
                    "--domains",
                    f'*.{lego_config["domains"]}',
                    "--email",
                    lego_config["acme_email"],
                    "--path",
                    "/data",
                    "--accept-tos",
                    "--pem",
                    "--dns",
                    lego_config["lego_provider"],
                    command,
                ],
                environment=lego_config,
                name=f"{self.listener_id[:8]}-tls",
            )
            c.start()
            c.wait(condition="running")

    @validate_call
    def smtpd(
        self,
        command=Literal["create", "reload_config", "restart"],
        ignore_exists: bool = True,
    ):
        pasta_pid_path = self.listener_volume_path / "pasta.pid"
        pidfile = pasta_pid_path.read_text() if pasta_pid_path.is_file() else None

        self.__generate_service_ports_configuration__()
        self.__generate_self_signed_certificate__()
        self.__generate_objects_configuration__()

        (self.listener_volume_path / "objects.config").write_text(
            str(self.running_config)
        )

        match command:
            case "create":
                with PodmanClient(base_url=self.podman_uri) as client:
                    if client.containers.exists(f"{self.listener_id[:8]}-smtpd"):
                        if ignore_exists == True:
                            c = client.containers.get(f"{self.listener_id[:8]}-smtpd")
                            if c.status != "exited":
                                c.stop()
                            c.remove()
                        else:
                            logger.warning("smtpd exists and will not be recreated")

                    self.wait_for_bindable()

                    c = client.containers.create(
                        image="docker.io/library/nginx:stable-alpine",
                        detach=True,
                        restart_policy={"Name": "on-failure", "MaximumRetryCount": 3},
                        labels={
                            "listener_id": self.listener_id,
                            "worker": "smtpd",
                            "io.containers.autoupdate": "registry",
                        },
                        mounts=[
                            {
                                "type": "bind",
                                "source": self.listener_volume,
                                "target": "/data",
                                "read_only": False,
                            }
                        ],
                        network_mode="pasta",
                        network_options={
                            "pasta": [
                                f"-P{self.listener_volume}/pasta.pid",
                                "--map-gw",
                                "-a10.0.2.0",
                                "-n24",
                                "-g10.0.2.1",
                            ]
                        },
                        ports=self.smtpd_ports,
                        command=[
                            "nginx",
                            "-g",
                            "daemon off;",
                            "-c",
                            "/data/nginx.conf",
                        ],
                        name=f"{self.listener_id[:8]}-smtpd",
                    )
                    c.start()
                    c.wait(condition="running")

            case "restart":
                with PodmanClient(base_url=self.podman_uri) as client:
                    c = client.containers.get(f"{self.listener_id[:8]}-smtpd")
                    if c.status != "exited":
                        c.stop()
                        c.wait(condition="exited")

                    while pasta_pid and self.wait_for_bindable():
                        try:
                            os.kill(pid, 15)
                        except OSError:
                            pass

                    c.start()

    def wait_for_bindable(self, timeout: int = 3):
        binding_tuples = helpers.flatten(
            [self.smtpd_ports[x] for x in self.smtpd_ports]
        )
        for binding in binding_tuples:
            _t = timeout
            while listeners_helpers.is_port_bindable(binding[0], binding[1]) == False:
                logger.info(
                    f"Waiting for {binding[0]}:{binding[1]} binding to become available ({_t})"
                )
                time.sleep(_t / 10)
                _t -= 0.1
                if _t <= 0:
                    raise Exception(f"{binding[0]}:{binding[1]} never became available")
