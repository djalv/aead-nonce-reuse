"""Export the editable office documents to PDF."""

import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile


def export_documents(source_root: Path, output_dir: Path) -> list[Path]:
    source_root = source_root.resolve()
    sources = [
        source_root / "report/report.docx",
        source_root / "slides/slides.pptx",
        source_root / "slides/demo-backup.pptx",
    ]
    for source in sources:
        if not source.is_file():
            raise FileNotFoundError(f"Document source not found: {source}")
        member = "word/document.xml" if source.suffix == ".docx" else "ppt/presentation.xml"
        try:
            with ZipFile(source) as archive:
                if member not in archive.namelist():
                    raise ValueError(f"Failed to export {source.name}: wrong document format.")
        except BadZipFile as error:
            raise ValueError(f"Failed to export {source.name}: invalid office document.") from error

    executable = shutil.which("libreoffice") or shutil.which("soffice")
    if executable is None:
        raise RuntimeError("Install LibreOffice to export DOCX and PPTX files to PDF.")

    output_dir = output_dir.resolve()
    with TemporaryDirectory(prefix="nonce-reuse-docs-") as temporary:
        workspace = Path(temporary)
        converted = workspace / "pdf"
        converted.mkdir()
        command = [
            executable,
            f"-env:UserInstallation={(workspace / 'profile').as_uri()}",
            "--headless",
            "--convert-to",
            "pdf",
            "--outdir",
            str(converted),
            *(str(source) for source in sources),
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Document export timed out after 60 seconds.") from error
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise ValueError(f"Failed to export documents: {detail}")

        exports = [converted / f"{source.stem}.pdf" for source in sources]
        for export in exports:
            if not export.is_file() or not export.read_bytes().startswith(b"%PDF-"):
                raise ValueError(f"Failed to export {export.name} with LibreOffice.")

        # A failed conversion must not replace the previous PDFs.
        output_dir.mkdir(parents=True, exist_ok=True)
        outputs = [output_dir / export.name for export in exports]
        for export, output in zip(exports, outputs, strict=True):
            shutil.copyfile(export, output)
    return outputs
