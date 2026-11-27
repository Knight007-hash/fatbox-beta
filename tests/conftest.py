import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_stagger(monkeypatch):
    """0.39.0: a helper younger than STAGGER_S counts as holding 1.1 GB of RAM; tests that are not about the RAM
    gate don't reserve. test_capa_speed sets it where the reservation itself is tested."""
    from fatbox import cli
    monkeypatch.setattr(cli, "STAGGER_S", 0)
