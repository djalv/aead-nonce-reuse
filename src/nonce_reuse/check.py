"""Verify the runtime without recording keys or experimental measurements."""

import os
import platform
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory


def run_checks() -> dict:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

    algorithms = {}
    message = b"authenticated encryption environment check"
    aad = b"nonce-reuse-study:environment-check"

    for name, cipher in (
        ("AES-256-GCM", AESGCM(AESGCM.generate_key(bit_length=256))),
        ("ChaCha20-Poly1305", ChaCha20Poly1305(ChaCha20Poly1305.generate_key())),
    ):
        # Each newly generated key is used for one encryption only.
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, message, aad)
        if cipher.decrypt(nonce, ciphertext, aad) != message:
            raise RuntimeError(f"{name}: the recovered message differs from the original.")
        modified = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        try:
            cipher.decrypt(nonce, modified, aad)
        except InvalidTag:
            pass
        else:
            raise RuntimeError(f"{name}: the modified ciphertext was not rejected.")
        algorithms[name] = {"round_trip": True, "tamper_rejected": True}

    # Keep font caches temporary and use a backend that needs no display server.
    with TemporaryDirectory(prefix="nonce-reuse-check-") as temporary:
        previous_config = os.environ.get("MPLCONFIGDIR")
        os.environ["MPLCONFIGDIR"] = str(Path(temporary) / "matplotlib")
        try:
            from matplotlib.backends.backend_agg import FigureCanvasAgg
            from matplotlib.figure import Figure

            figure = Figure(figsize=(2, 1))
            FigureCanvasAgg(figure)
            figure.subplots().plot([0, 1], [0, 1])
            output = Path(temporary) / "check.png"
            figure.savefig(output, format="png")
            if not output.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
                raise RuntimeError("The figure generation check failed.")
        finally:
            if previous_config is None:
                os.environ.pop("MPLCONFIGDIR", None)
            else:
                os.environ["MPLCONFIGDIR"] = previous_config

    return {
        "python": platform.python_version(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "dependencies": {package: version(package) for package in ("cryptography", "matplotlib")},
        "openssl": default_backend().openssl_version_text(),
        "checks": {"algorithms": algorithms, "matplotlib_png": True},
    }
