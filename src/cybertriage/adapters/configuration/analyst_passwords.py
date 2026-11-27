"""Local operator provisioning; passwords are never written or printed."""

import os
from pathlib import Path
import re
import stat
import tempfile

import yaml

from cybertriage.adapters.configuration.analyst_keys import AnalystKeyStore
from cybertriage.adapters.configuration.password_hashing import ScryptPasswords
from cybertriage.adapters.configuration.yaml_files import _read_yaml


def set_analyst_password(path: Path, analyst_id: str, username: str, password: str):
    username=username.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}",username):
        raise ValueError("Username must have 3-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter.")
    if path.is_symlink():
        raise ValueError("Analyst configuration must not be a symbolic link.")
    original=path.read_bytes()
    document=_read_yaml(path)
    AnalystKeyStore(path).load(document)
    rows=[row for row in document["principals"] if row["id"]==analyst_id]
    if len(rows)!=1:
        raise ValueError("Choose an existing analyst principal; password provisioning does not grant permissions.")
    if any(row.get("username")==username and row["id"]!=analyst_id for row in document["principals"]):
        raise ValueError("Username is already assigned to another analyst.")
    rows[0].update(username=username,password_hash=ScryptPasswords().hash(password))
    AnalystKeyStore(path).load(document)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode="w",encoding="utf-8",dir=path.parent,delete=False,newline="\n") as file:
            temporary=Path(file.name)
            yaml.safe_dump(document,file,sort_keys=False,allow_unicode=True)
            file.flush();os.fsync(file.fileno())
        temporary.chmod(stat.S_IMODE(path.stat().st_mode))
        if path.read_bytes()!=original:
            raise ValueError("Analyst configuration changed during provisioning. Retry with its current contents.")
        os.replace(temporary,path)
    finally:
        if temporary is not None and temporary.exists():temporary.unlink()
