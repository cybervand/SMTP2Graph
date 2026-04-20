import argparse
import getpass
import hashlib
import secrets
import shutil
import string
import sys
from pathlib import Path


SALT_CHARS = string.ascii_letters + string.digits
SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a starter .env and admin password hash for SMTP2Graph."
    )
    parser.add_argument(
        "--force-env",
        action="store_true",
        help="Overwrite .env from .env.example even if it already exists.",
    )
    parser.add_argument(
        "--force-password-hash",
        action="store_true",
        help="Overwrite plugin-ui/data/admin-password.hash even if it already exists.",
    )
    parser.add_argument(
        "--admin-password-file",
        type=Path,
        help="Read the admin password from a file instead of prompting.",
    )
    return parser.parse_args()


def make_scrypt_hash(password: str) -> str:
    salt = "".join(secrets.choice(SALT_CHARS) for _ in range(16))
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    ).hex()
    return f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}${salt}${digest}"


def ensure_env_file(repo_root: Path, force: bool) -> None:
    env_example = repo_root / ".env.example"
    env_file = repo_root / ".env"

    if not env_example.exists():
        raise FileNotFoundError(f"Missing template file: {env_example}")

    if env_file.exists() and not force:
        print(f"Keeping existing {env_file.name}")
        return

    shutil.copyfile(env_example, env_file)
    print(f"Wrote {env_file.name} from {env_example.name}")


def read_admin_password(password_file: Path | None) -> str:
    if password_file:
        password = password_file.read_text(encoding="utf-8").strip()
        if not password:
            raise ValueError(f"Password file is empty: {password_file}")
        return password

    if not sys.stdin.isatty():
        raise RuntimeError(
            "No interactive terminal available. Use --admin-password-file to provide a password."
        )

    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm admin password: ")

    if not password:
        raise ValueError("Admin password may not be empty.")
    if password != confirm:
        raise ValueError("Passwords did not match.")

    return password


def ensure_admin_password_hash(
    repo_root: Path, password_file: Path | None, force: bool
) -> None:
    hash_file = repo_root / "plugin-ui" / "data" / "admin-password.hash"

    if hash_file.exists() and not force:
        print(f"Keeping existing {hash_file.relative_to(repo_root)}")
        return

    password = read_admin_password(password_file)
    hash_file.parent.mkdir(parents=True, exist_ok=True)
    hash_file.write_text(make_scrypt_hash(password), encoding="utf-8")
    print(f"Wrote {hash_file.relative_to(repo_root)}")


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent

    ensure_env_file(repo_root, args.force_env)
    ensure_admin_password_hash(
        repo_root,
        args.admin_password_file,
        args.force_password_hash,
    )

    print("")
    print("Next steps:")
    print("1. Review .env and adjust IPs, ports, and cert paths for the server.")
    print("2. Place your smtp2graph config in plugin-ui/data/config.yml.")
    print("3. Run: docker compose up -d --build smtp2graph-admin")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
