import argparse
import json
import os
from pathlib import Path
import shutil
import sys

from . import __version__
from .core import StallionError, Store


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prepared copy-on-write agent workspaces on macOS")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--root", default=os.environ.get("STALLIONFS_HOME", str(Path.home() / "Library/Application Support/stallionfs")))
    parser.add_argument("--json", action="store_true", help="Print structured output")
    commands = parser.add_subparsers(dest="action", required=True)
    prepare = commands.add_parser("prepare", help="Prepare a clean commit once")
    prepare.add_argument("source")
    prepare.add_argument("--ref", default="HEAD")
    prepare.add_argument("--key", required=True, help="Toolchain/environment cache key; change when the environment changes")
    create = commands.add_parser("create", help="Clone a prepared seed")
    create.add_argument("seed")
    create.add_argument("--name", default="")
    listing = commands.add_parser("list", help="List stored workspaces, seeds or trash")
    listing.add_argument("kind", nargs="?", choices=["workspaces", "seeds", "trash"], default="workspaces")
    for action in ("remove", "restore"):
        command = commands.add_parser(action, help="Move a workspace to trash" if action == "remove" else "Restore a trashed workspace")
        command.add_argument("id")
    gc = commands.add_parser("gc", help="Preview or permanently delete eligible trash")
    gc.add_argument("--yes", action="store_true", help="Permanently delete the listed trash")
    gc.add_argument("--older-than", type=float, default=24, metavar="HOURS")
    forget = commands.add_parser("forget", help="Preview or delete a regenerable seed")
    forget.add_argument("seed")
    forget.add_argument("--yes", action="store_true")
    commands.add_parser("doctor", help="Test native cloning and write isolation")
    raw = list(sys.argv[1:] if argv is None else argv)
    setup = []
    if "--" in raw:
        index = raw.index("--")
        raw, setup = raw[:index], raw[index + 1:]
    args = parser.parse_args(raw)
    if setup and args.action != "prepare":
        parser.error("Only prepare accepts a command after --")
    try:
        store = Store(args.root)
        if args.action == "prepare":
            result = store.prepare(args.source, ref=args.ref, key=args.key, command=setup)
            text = result["id"]
        elif args.action == "create":
            result = store.create(args.seed, name=args.name)
            text = result["path"]
        elif args.action == "list":
            result = store.list(args.kind)
            text = "\n".join(f"{item['id']}\t{item.get('name', '')}\t{item['path']}" for item in result)
        elif args.action in ("remove", "restore"):
            result = store.move(args.id, restore=args.action == "restore")
            text = result["path"]
        elif args.action == "gc":
            items = store.gc(older_than=args.older_than * 3600, yes=args.yes)
            result = {"deleted" if args.yes else "would_delete": items}
            text = json.dumps(result)
        elif args.action == "forget":
            result = store.forget(args.seed, yes=args.yes)
            text = json.dumps(result)
        else:
            result = store.doctor()
            text = json.dumps(result, indent=2)
        print(json.dumps(result, sort_keys=True) if args.json else text)
        return 0
    except (StallionError, OSError, shutil.Error) as exc:
        print(json.dumps({"error": str(exc)}) if args.json else f"stallionfs: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("stallionfs: interrupted; no partial workspace was published", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
