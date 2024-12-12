import glob
import os

from aiotinydb import AIOTinyDB as TinyDB
from aiotinydb.storage import AIOStorage
from pydantic import validate_call
from tinydb import Query
from tinydb.table import Document
from tinydb.queries import QueryInstance
from typing import Literal
from utils.datetimes import ntime_utc_now
from utils.helpers import is_path_within_cwd

__all__ = ["TinyDB", "Query", "Document", "TINYDB_PARAMS", "IN_MEMORY_DB"]

TinyDB.DEFAULT_TABLE_KWARGS = {"cache_size": 0}
TINYDB_PARAMS = {"filename": "database/main", "indent": 2, "sort_keys": True}

IN_MEMORY_DB = dict()
