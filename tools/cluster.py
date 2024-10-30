import aiohttp
import os

from config import defaults, logger
from pydantic import validate_call
from utils.crypto import fernet_decrypt, fernet_encrypt
from utils.datetimes import last_modified_http
from utils.helpers import ensure_list, is_path_within_cwd


@validate_call
async def get_peer_files(cluster, peers: str | list | set, files: str | list | set):
    if isinstance(files, str):
        files = ensure_list(files)
    if isinstance(peers, str):
        peers = ensure_list(peers)

    for file in files:
        for peer in peers:
            file_dest = f"peer_files/{peer}/{file}"
            assert is_path_within_cwd(file_dest) == True, "Illegal path"
            os.makedirs(os.path.dirname(file_dest), exist_ok=True)
            if peer in cluster.connections and cluster.connections[peer]["meta"]:
                async with aiohttp.ClientSession() as client_session:
                    async with client_session.post(
                        "https://{http_bind}/file_read".format(
                            http_bind=cluster.connections[peer]["meta"]["http"]
                        ),
                        server_hostname=defaults.HOSTNAME,
                        headers={
                            "Host": defaults.HOSTNAME,
                            "If-Modified-Since": last_modified_http(file_dest),
                        },
                        data={"file": file},
                    ) as resp:
                        if resp.status != 304:
                            payload = await resp.content.read()
                            decrypted = fernet_decrypt(
                                payload,
                                defaults.SECRET_KEY,
                            )
                            with open(file_dest, "w") as f:
                                f.write(decrypted)


@validate_call
async def write_peer_files(cluster, peers: str | list | set, files: str | list | set):
    if isinstance(files, str):
        files = ensure_list(files)
    if isinstance(peers, str):
        peers = ensure_list(peers)

    for file in files:
        file_dest = f"peer_files/{defaults.CLUSTER_PEERS_ME}/{file}"
        assert is_path_within_cwd(file) == True, "Illegal path"

        with open(file, "r") as f:
            encrypted = fernet_encrypt(
                f.read(),
                defaults.SECRET_KEY,
            ).decode("ascii")

        for peer in peers:
            async with aiohttp.ClientSession() as client_session:
                async with client_session.post(
                    "https://{http_bind}/file_write".format(
                        http_bind=cluster.connections[peer]["meta"]["http"]
                    ),
                    server_hostname=defaults.HOSTNAME,
                    headers={
                        "Host": defaults.HOSTNAME,
                    },
                    data={
                        "file": file_dest,
                        "data": encrypted,
                    },
                ) as resp:
                    assert resp.status == 200
