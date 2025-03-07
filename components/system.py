import os
import glob
from components.models.system import SystemSettingsBase
from components.database import TinyDB, TINYDB_PARAMS


async def get_system_settings():
    async with TinyDB(**TINYDB_PARAMS) as db:
        settings = db.table("system_settings").get(doc_id=1) or {}
        return SystemSettingsBase.parse_obj(settings).dict()


def list_application_log_files():
    yield "logs/application.log"
    for peer_dir in glob.glob("peer_files/*"):
        peer_log = os.path.join(peer_dir, "logs/application.log")
        if os.path.isfile(peer_log):
            yield peer_log
