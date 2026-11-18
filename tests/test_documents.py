import subprocess
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from nonce_reuse.documents import export_documents


@pytest.fixture
def office_sources(tmp_path):
    root = tmp_path / "source"
    for name in ("report/report.docx", "slides/slides.pptx", "slides/demo-backup.pptx"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        member = "word/document.xml" if path.suffix == ".docx" else "ppt/presentation.xml"
        with ZipFile(path, "w") as archive:
            archive.writestr(member, "<placeholder/>")
    return root


def test_missing_converter_preserves_existing_documents(office_sources, tmp_path, monkeypatch):
    output = tmp_path / "output"
    output.mkdir()
    previous = output / "report.pdf"
    previous.write_bytes(b"previous report")
    monkeypatch.setattr("nonce_reuse.documents.shutil.which", lambda name: None)

    with pytest.raises(RuntimeError, match="Install LibreOffice"):
        export_documents(office_sources, output)
    assert previous.read_bytes() == b"previous report"


def test_incomplete_export_does_not_replace_previous_pdfs(office_sources, tmp_path, monkeypatch):
    output = tmp_path / "output"
    output.mkdir()
    previous = {name: b"previous " + name.encode() for name in ("report.pdf", "slides.pdf")}
    for name, data in previous.items():
        (output / name).write_bytes(data)

    def incomplete(command, **kwargs):
        destination = Path(command[command.index("--outdir") + 1])
        (destination / "report.pdf").write_bytes(b"%PDF-new report")
        return SimpleNamespace(returncode=0, stdout="", stderr="conversion failed")

    monkeypatch.setattr("nonce_reuse.documents.shutil.which", lambda name: "/usr/bin/libreoffice")
    monkeypatch.setattr("nonce_reuse.documents.subprocess.run", incomplete)
    with pytest.raises(ValueError, match="Failed to export slides.pdf"):
        export_documents(office_sources, output)
    assert {name: (output / name).read_bytes() for name in previous} == previous


def test_export_timeout_does_not_create_output(office_sources, tmp_path, monkeypatch):
    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 60)

    output = tmp_path / "output"
    monkeypatch.setattr("nonce_reuse.documents.shutil.which", lambda name: "/usr/bin/libreoffice")
    monkeypatch.setattr("nonce_reuse.documents.subprocess.run", timeout)
    with pytest.raises(RuntimeError, match="timed out"):
        export_documents(office_sources, output)
    assert not output.exists()


def test_wrong_office_package_is_rejected_before_export(office_sources, tmp_path):
    with ZipFile(office_sources / "slides/slides.pptx", "w") as archive:
        archive.writestr("word/document.xml", "<document/>")
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="wrong document format"):
        export_documents(office_sources, output)
    assert not output.exists()


def test_converter_failure_does_not_create_output(office_sources, tmp_path, monkeypatch):
    monkeypatch.setattr("nonce_reuse.documents.shutil.which", lambda name: "/usr/bin/libreoffice")
    monkeypatch.setattr(
        "nonce_reuse.documents.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="export failed"),
    )
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="export failed"):
        export_documents(office_sources, output)
    assert not output.exists()
