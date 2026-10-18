from app.config import FIXTURE_DIR
from app.demo import run


def test_demo_is_deterministic_and_tells_the_story(tmp_path):
    a = run([tmp_path / "none", FIXTURE_DIR], quiet=True)
    b = run([tmp_path / "none", FIXTURE_DIR], quiet=True)
    assert a["story"] == b["story"] and a["metrics"] == b["metrics"] and a["events"] == b["events"]
    kinds = [s["kind"] for s in a["story"]]
    texts = " ".join(s["text"] for s in a["story"])
    assert "fingerprint" in kinds and "rule" in kinds and "alert" in kinds
    assert "RETURNING BEHAVIOUR" in texts and "Auto-applied" in texts
    assert a["events"]["dropped"] > 0
    assert a["metrics"]["returning"]["rate"] == 1.0
