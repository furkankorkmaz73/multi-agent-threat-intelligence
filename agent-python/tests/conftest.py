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
        import pymongo  # noqa: F401
        from pymongo.errors import PyMongoError  # noqa: F401
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

    errors_stub.PyMongoError = PyMongoError
    pymongo_stub.errors = errors_stub

    sys.modules["pymongo"] = pymongo_stub
    sys.modules["pymongo.errors"] = errors_stub


_install_pymongo_stub_if_missing()
