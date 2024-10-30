from aiotinydb import AIOTinyDB as TinyDB
from aiotinydb.storage import AIOStorage
from tinydb import Query
from tinydb.table import Document

__all__ = ["TinyDB", "Query", "Document", "TINYDB_PARAMS"]
TinyDB.DEFAULT_TABLE_KWARGS = {"cache_size": 0}
TINYDB_PARAMS = {"filename": "database/main"}
