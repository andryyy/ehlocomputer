import re
import uuid

from config import defaults
from config.database import *
from pydantic import AfterValidator, validate_call
from typing import Annotated, Literal
from utils import helpers
from views.objects import tools as objects_helpers


@validate_call
def get_config_by_id(
    config_id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x)))],
    realm_path: str,
):
    with TinyDB(**defaults.TINYDB, path=realm_path) as db:
        return db.table("configs").get(Query().id == config_id)


@validate_call
def get_config_by_name(name: str, realm_path: str):
    with TinyDB(**defaults.TINYDB, path=realm_path) as db:
        return db.table("configs").get(Query().name == name)


@validate_call
def get_config_by_suffix(suffix: str, realm_path: str):
    with TinyDB(**defaults.TINYDB, path=realm_path) as db:
        return db.table("configs").search(
            Query().name.matches(f"(.*\.|^){suffix}$", flags=re.IGNORECASE)
        )


@validate_call
def translate_raw_config(raw_config: dict, realm_path: str):
    configuration = dict()

    for domain, data in raw_config.items():
        domain_object = objects_helpers.get_object_by_id(
            object_type="domains", object_id=domain, realm_path=realm_path
        )
        if not domain_object:
            continue

        configuration.update(
            {
                domain: dict(),
            }
        )

        domain_config = data["object_config"][domain]
        domain_name = domain_object["name"]

        configuration[domain].update(
            {
                "settings": [],
                "recipients": [],
                "data_object": {
                    "objectId": domain,
                    "objectName": domain_name,
                    "objectType": "domains",
                },
            }
        )

        for setting in helpers.ensure_list(domain_config.get("settings", [])):
            setting_object = objects_helpers.get_object_by_id(
                object_type="settings", object_id=setting, realm_path=realm_path
            )
            if not setting_object:
                continue

            setting_name = setting_object["name"]
            domain_setting = {
                setting: {
                    "data_object": {
                        "objectId": setting,
                        "objectName": setting_name,
                        "objectData": {
                            setting_object["settings_rule"]: {
                                k: v
                                for k, v in setting_object.items()
                                if k.startswith(setting_object["source"])
                                and v not in [None, ""]
                            }
                        },
                        "objectType": "settings",
                    },
                }
            }
            if domain_setting not in configuration[domain]["settings"]:
                configuration[domain]["settings"].append(domain_setting)

        for recipient in helpers.ensure_list(domain_config.get("recipients", [])):
            recipient_object = objects_helpers.get_object_by_id(
                object_type="recipients", object_id=recipient, realm_path=realm_path
            )
            if not recipient_object:
                continue

            recipient_name = recipient_object["name"]
            recipient_settings = []

            for setting in helpers.ensure_list(
                data["object_config"].get(recipient, {}).get("settings", [])
            ):
                setting_object = objects_helpers.get_object_by_id(
                    object_type="settings", object_id=setting, realm_path=realm_path
                )
                if not setting_object:
                    continue

                setting_name = setting_object["name"]
                recipient_setting = {
                    setting: {
                        "data_object": {
                            "objectId": setting,
                            "objectName": setting_name,
                            "objectData": {
                                setting_object["settings_rule"]: {
                                    k: v
                                    for k, v in setting_object.items()
                                    if k.startswith(setting_object["source"])
                                    and v not in [None, ""]
                                }
                            },
                            "objectType": "settings",
                        },
                    },
                }
                if recipient_setting not in recipient_settings:
                    recipient_settings.append(recipient_setting)

            configuration[domain]["recipients"].append(
                {
                    recipient: {
                        "settings": recipient_settings,
                        "data_object": {
                            "objectId": recipient,
                            "objectName": recipient_name,
                            "objectType": "recipients",
                        },
                    },
                }
            )

    return configuration
