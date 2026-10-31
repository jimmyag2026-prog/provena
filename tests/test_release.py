import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_version_is_single_sourced():
    import provena

    text = (ROOT / "src" / "provena" / "_version.py").read_text()
    assert f'__version__ = "{provena.__version__}"' in text
    assert 'dynamic = ["version"]' in (ROOT / "pyproject.toml").read_text()


def test_bump_script_dates_changelog_and_bumps(tmp_path):
    root = tmp_path / "repo"
    (root / "src" / "provena").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "src" / "provena" / "_version.py").write_text('__version__ = "0.0.0"\n')
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n\n### Added\n- x\n")
    script = (ROOT / "scripts" / "bump_version.py").read_text()
    (root / "scripts" / "bump_version.py").write_text(script)
    subprocess.run([sys.executable, str(root / "scripts" / "bump_version.py"), "minor"],
                   check=True, capture_output=True)
    assert '"0.1.0"' in (root / "src" / "provena" / "_version.py").read_text()
    log = (root / "CHANGELOG.md").read_text()
    assert re.search(r"## \[Unreleased\]\n\n## \[0\.1\.0\] - \d{4}-\d{2}-\d{2}\n", log)
    bad = subprocess.run([sys.executable, str(root / "scripts" / "bump_version.py"), "0.0.5"],
                         capture_output=True, text=True)
    assert bad.returncode != 0 and "not newer" in bad.stderr
