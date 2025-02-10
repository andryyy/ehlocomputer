from config.database import *
from config import defaults
from config.logs import logger


class CommandHandler(Cluster):
    async def process_command(cmd: str):
        if cmd.startswith("PATCHTABLE") or cmd.startswith("FULLTABLE"):
            if cmd.startswith("FULLTABLE") and IN_MEMORY_DB["peer_critical"].get(
                peer_info["bind"]
            ):
                del IN_MEMORY_DB["peer_critical"][peer_info["bind"]]

            if (
                cmd.startswith("PATCHTABLE")
                and IN_MEMORY_DB["peer_critical"].get(peer_info["bind"])
                == "CRIT:TABLE_HASH_MISMATCH"
            ):
                await self.send_command(
                    CritErrors.NO_TRUST.value,
                    [peer_info["bind"]],
                    ticket=ticket,
                )
                continue

            _, _, payload = cmd.partition(" ")
            table_w_hash, table_payload = payload.split(" ")
            table, table_digest = table_w_hash.split("@")

            db_params = evaluate_db_params(ticket)

            async with TinyDB(**db_params) as db:
                if not table in db.tables():
                    await self.send_command(
                        CritErrors.NO_SUCH_TABLE.value,
                        [peer_info["bind"]],
                        ticket=ticket,
                    )
                else:
                    try:
                        if cmd.startswith("PATCHTABLE"):
                            table_data = {
                                doc.doc_id: doc for doc in db.table(table).all()
                            }
                            local_table_digest = dict_digest_sha1(table_data)

                            if local_table_digest != table_digest:
                                await self.send_command(
                                    CritErrors.TABLE_HASH_MISMATCH.value,
                                    [peer_info["bind"]],
                                    ticket=ticket,
                                )
                                continue

                            diff = json.loads(base64.b64decode(table_payload))
                            for doc_id, doc in diff["changed"].items():
                                db.table(table).upsert(Document(doc, doc_id=doc_id))
                            for doc_id, doc in diff["added"].items():
                                db.table(table).insert(Document(doc, doc_id=doc_id))
                            db.table(table).remove(
                                Query().id.one_of(
                                    [doc["id"] for doc in diff["removed"].values()]
                                )
                            )

                        elif cmd.startswith("FULLTABLE"):
                            insert_data = json.loads(base64.b64decode(table_payload))
                            db.table(table).truncate()
                            for doc_id, doc in insert_data.items():
                                db.table(table).insert(Document(doc, doc_id=doc_id))

                        await self.send_command(
                            "ACK", [peer_info["bind"]], ticket=ticket
                        )

                    except Exception as e:
                        await self.send_command(
                            CritErrors.CANNOT_APPLY.value,
                            [peer_info["bind"]],
                            ticket=ticket,
                        )
                        continue
