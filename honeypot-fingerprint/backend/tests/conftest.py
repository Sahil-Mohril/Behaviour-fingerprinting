import os
import sys
import tempfile
from pathlib import Path

# Isolate tests from the real data/state folders before the app modules are imported.
_TMP = Path(tempfile.mkdtemp(prefix="hfp-tests-"))
os.environ["HFP_STATE_DIR"] = str(_TMP / "state")
os.environ["HFP_DATA_DIR"] = str(_TMP / "no-data")
os.environ["HFP_NO_DB"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from app.adapters.catalog import Catalog  # noqa: E402
from app.config import FIXTURE_DIR  # noqa: E402

BASE = 1_800_000_000.0


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURE_DIR


@pytest.fixture(scope="session")
def catalog(tmp_path_factory) -> Catalog:
    c = Catalog([FIXTURE_DIR], tmp_path_factory.mktemp("cat") / "catalog.json")
    c.refresh()
    return c


@pytest.fixture(scope="session")
def source_ids(catalog) -> dict:
    return {s["name"]: s["id"] for s in catalog.list()}
