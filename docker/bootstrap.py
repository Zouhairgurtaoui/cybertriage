"""Initialize named-volume ownership and private API TLS without touching host trust."""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
from uuid import uuid4


DATA = Path("/app/data")
TLS = Path("/run/api-tls")
TRUST = Path("/run/public-trust")


def openssl(*arguments):
    result = subprocess.run(["openssl", *arguments], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30)
    if result.returncode:
        raise ValueError("Local API TLS provisioning/validation failed. Stop the stack before inspecting or replacing its TLS volumes.")


def validate_tls():
    openssl("verify", "-CAfile", str(TRUST / "ca.pem"), str(TLS / "analyst.pem"))
    openssl("x509", "-in", str(TLS / "analyst.pem"), "-noout", "-checkend", "86400")
    openssl("x509", "-in", str(TLS / "analyst.pem"), "-noout", "-checkhost", "analyst-api")


def initialize_tls():
    expected = [TLS / "analyst.pem", TLS / "analyst-key.pem", TLS / "ca.pem", TRUST / "ca.pem"]
    if all(path.is_file() for path in expected):
        validate_tls()
        return
    if any(path.exists() for path in expected):
        raise ValueError("Partial API TLS material exists. Existing keys are never silently overwritten.")
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        ca_key, ca, key, csr, cert = [temporary / name for name in ("ca-key.pem", "ca.pem", "key.pem", "request.pem", "cert.pem")]
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "365",
            "-subj", "/CN=CyberTriage private Compose CA", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(ca_key), "-out", str(ca))
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=analyst-api", "-keyout", str(key), "-out", str(csr))
        extensions = temporary / "extensions.cnf"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:analyst-api,DNS:localhost,IP:127.0.0.1\n", encoding="ascii")
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-set_serial", str(int(uuid4().hex, 16)),
            "-sha256", "-days", "365", "-extfile", str(extensions), "-out", str(cert))
        openssl("verify", "-CAfile", str(ca), str(cert))
        for target, source in ((TLS / "analyst.pem", cert), (TLS / "analyst-key.pem", key), (TLS / "ca.pem", ca), (TRUST / "ca.pem", ca)):
            with target.open("xb") as file:
                file.write(source.read_bytes())
            target.chmod(0o600 if "key" in target.name else 0o644)
            os.chown(target, 10001 if target.parent == TLS else 0, 10001 if target.parent == TLS else 0)
    # The CA signing key existed only in temporary storage; the frontend sees public trust only.


def main():
    for directory in (DATA, TLS, TRUST):
        directory.mkdir(parents=True, exist_ok=True)
    TLS.chmod(0o700)
    os.chown(TLS, 10001, 10001)
    TRUST.chmod(0o755)
    initialized = DATA / ".container-initialized.json"
    with (DATA / ".runtime.lock").open("a+b") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if not initialized.is_file():
                raise ValueError("Backend data is in use before initialization completed.")
            validate_tls()
            print("Existing stack initialization is valid.")
            return
        for name in ("alerts", "catalogs", "chroma", "cache", "reports"):
            (DATA / name).mkdir(exist_ok=True)
        os.chown(DATA, 10001, 10001)
        os.chown(DATA / ".runtime.lock", 10001, 10001)
        for name in ("alerts", "catalogs", "chroma", "cache", "reports"):
            os.chown(DATA / name, 10001, 10001)
        initialize_tls()
        initialized.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
        os.chown(initialized, 10001, 10001)
    print("Data volume and private API TLS are ready.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(f"Bootstrap failed: {type(error).__name__}: {error}") from None
