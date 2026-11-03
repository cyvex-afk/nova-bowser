"""
Signed updates for Nova (Ed25519). Nova refuses any update that isn't signed with YOUR key.

  pip install cryptography

  1) One time:   python sign_update.py keygen
        -> writes update_private.key (KEEP SECRET, never upload) and prints the PUBLIC key.
        -> paste the public key into Nova: gear panel -> Advanced -> "Update public key".

  2) Each release (after build.bat produced Output\\NovaSetup.exe):
        python sign_update.py sign --version 1.2.1 --url https://your.host/NovaSetup.exe --notes "What's new"
        -> writes update.json. Upload NovaSetup.exe and update.json over HTTPS.
        -> set Nova's "Update manifest URL" to the update.json URL.
"""
import argparse, base64, hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ap = argparse.ArgumentParser()
sub = ap.add_subparsers(dest="cmd", required=True)
sub.add_parser("keygen")
s = sub.add_parser("sign")
s.add_argument("--version", required=True)
s.add_argument("--url", required=True)
s.add_argument("--setup", default=r"Output\NovaSetup.exe")
s.add_argument("--notes", default="")
s.add_argument("--key", default="update_private.key")
a = ap.parse_args()

if a.cmd == "keygen":
    k = Ed25519PrivateKey.generate()
    raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    Path("update_private.key").write_text(base64.b64encode(raw).decode())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print("Saved update_private.key (keep it secret and backed up).")
    print("PUBLIC KEY (paste into Nova):", base64.b64encode(pub).decode())
else:
    if not a.url.startswith("https://"):
        sys.exit("URL must be https")
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(a.key).read_text()))
    sha = hashlib.sha256(Path(a.setup).read_bytes()).hexdigest()
    sig = base64.b64encode(key.sign(f"{a.version}|{a.url}|{sha}".encode())).decode()
    Path("update.json").write_text(json.dumps(
        {"version": a.version, "url": a.url, "sha256": sha, "sig": sig, "notes": a.notes}, indent=1))
    print("Wrote update.json  sha256:", sha)
