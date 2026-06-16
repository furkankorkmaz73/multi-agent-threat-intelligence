import sys
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


def _install_pymongo_stub_if_missing():
    """Allow unit tests to be collected in minimal environments without pymongo."""
    try:
        from bson import ObjectId  # noqa: F401
        from bson.errors import InvalidId  # noqa: F401
        import pymongo  # noqa: F401
        from pymongo.errors import PyMongoError, ServerSelectionTimeoutError  # noqa: F401
        return
    except Exception:
        pass

    class _DummyCursor(list):
        def sort(self, *_args, **_kwargs):
            return self

        def limit(self, *_args, **_kwargs):
            return self

    class _DummyCollection:
        def create_index(self, *_args, **_kwargs):
            return None

        def find(self, *_args, **_kwargs):
            return _DummyCursor()

        def find_one(self, *_args, **_kwargs):
            return None

        def update_one(self, *_args, **_kwargs):
            return None

        def count_documents(self, *_args, **_kwargs):
            return 0

    class _DummyDatabase:
        def __getitem__(self, _name):
            return _DummyCollection()

    class _DummyMongoClient:
        def __init__(self, *_args, **_kwargs):
            self.admin = types.SimpleNamespace(command=lambda *_a, **_k: {"ok": 1})

        def __getitem__(self, _name):
            return _DummyDatabase()

    pymongo_stub = types.ModuleType("pymongo")
    pymongo_stub.MongoClient = _DummyMongoClient
    pymongo_stub.DESCENDING = -1
    pymongo_stub.ASCENDING = 1

    errors_stub = types.ModuleType("pymongo.errors")

    class PyMongoError(Exception):
        pass

    class ServerSelectionTimeoutError(PyMongoError):
        pass

    errors_stub.PyMongoError = PyMongoError
    errors_stub.ServerSelectionTimeoutError = ServerSelectionTimeoutError
    pymongo_stub.errors = errors_stub

    bson_errors_stub = types.ModuleType("bson.errors")

    class InvalidId(Exception):
        pass

    class ObjectId:
        def __init__(self, value=None):
            if value is None:
                self.value = "000000000000000000000000"
                return
            if isinstance(value, ObjectId):
                self.value = value.value
                return
            text = str(value)
            if len(text) != 24:
                raise InvalidId(f"{text!r} is not a valid ObjectId")
            self.value = text

        def __str__(self):
            return self.value

        def __repr__(self):
            return f"ObjectId({self.value!r})"

        def __eq__(self, other):
            return isinstance(other, ObjectId) and self.value == other.value

    bson_stub = types.ModuleType("bson")
    bson_stub.ObjectId = ObjectId
    bson_errors_stub.InvalidId = InvalidId
    bson_stub.errors = bson_errors_stub

    sys.modules["pymongo"] = pymongo_stub
    sys.modules["pymongo.errors"] = errors_stub
    sys.modules["bson"] = bson_stub
    sys.modules["bson.errors"] = bson_errors_stub


_install_pymongo_stub_if_missing()
