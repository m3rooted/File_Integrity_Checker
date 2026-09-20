"""Small SHA-256 baseline checker for log files."""

# File Integrity Checker
# Copyright (c) 2026 QuangND
# All Rights Reserved.

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path


def state_file():
    root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return root / "file-integrity-checker" / "hashes.json"


def validate_state_path(path):
    if os.name != "posix":
        return
    for item in (path.parent, path):
        if item.is_symlink():
            raise ValueError(f"unsafe baseline path (symbolic link): {item}")
        if item.exists():
            details = item.stat()
            if details.st_uid != os.getuid() or details.st_mode & 0o077:
                raise ValueError(f"unsafe baseline permissions: {item}")


def load_hashes(path):
    validate_state_path(path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read baseline {path}: {exc}") from exc
    if not isinstance(data, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in data.items()
    ):
        raise ValueError(f"invalid baseline format: {path}")
    return data


def save_hashes(path, hashes):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    validate_state_path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".hashes-",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            if os.name == "posix":
                os.chmod(temporary, 0o600)
            json.dump(hashes, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def selected_files(path):
    if not path.exists():
        raise ValueError(f"path does not exist: {path}")
    if path.is_file():
        return [path.resolve()]
    if not path.is_dir():
        raise ValueError(f"not a regular file or directory: {path}")
    try:
        files = sorted(child.resolve() for child in path.iterdir() if child.is_file())
    except OSError as exc:
        raise ValueError(f"cannot read directory {path}: {exc}") from exc
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check SHA-256 integrity of log files")
    parser.add_argument("command", choices=("init", "check", "update"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    try:
        files = selected_files(args.path)
        if args.command == "init" and not files:
            raise ValueError(f"directory has no regular files: {args.path}")
        if args.command == "update" and len(files) != 1:
            raise ValueError("update requires a single file")
        baseline_path = state_file()
        hashes = load_hashes(baseline_path)
        if args.command == "check":
            failed = False
            if args.path.is_dir():
                directory = args.path.resolve()
                current_keys = {str(file) for file in files}
                stored_keys = {key for key in hashes if Path(key).parent == directory}
                if not stored_keys and not files:
                    raise ValueError(f"no stored baseline for {directory}")
                for stored in sorted(stored_keys):
                    if stored not in current_keys:
                        print(f"{stored}: Status: Missing")
                        failed = True
            for file in files:
                key = str(file)
                if key not in hashes:
                    print(f"Error: no stored baseline for {file}", file=sys.stderr)
                    failed = True
                    continue
                current = sha256_file(file)
                status = "Unmodified" if current == hashes[key] else "Modified (Hash mismatch)"
                if len(files) > 1:
                    print(f"{file}: Status: {status}")
                else:
                    print(f"Status: {status}")
                failed |= current != hashes[key]
            return 1 if failed else 0

        if args.command == "update" and str(files[0]) not in hashes:
            raise ValueError(f"no stored baseline for {files[0]}")
        computed = {str(file): sha256_file(file) for file in files}
        hashes.update(computed)
        save_hashes(baseline_path, hashes)
        print("Hash updated successfully." if args.command == "update" else "Hashes stored successfully.")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
