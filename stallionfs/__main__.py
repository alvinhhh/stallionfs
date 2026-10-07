import argparse
import json
import os
from pathlib import Path
import shutil
import sys

from . import __version__
from .core import StallionError, Store


def main(argv=None):
    parser = argparse.ArgumentParser(description="Filesystem tools for macOS")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--root", default=os.environ.get("STALLIONFS_HOME", str(Path.home() / "Library/Application Support/stallionfs")))
    parser.add_argument("--json", action="store_true", help="Print structured output")
    commands = parser.add_subparsers(dest="action", required=True)
    scan = commands.add_parser("scan", help="Count files and logical bytes using bulk metadata reads")
    scan.add_argument("path", help="Directory to scan; symlinks and nested volumes are not followed")
    prepare = commands.add_parser("prepare", help="Prepare a clean commit once")
    prepare.add_argument("source")
    prepare.add_argument("--ref", default="HEAD")
    prepare.add_argument("--key", required=True, help="Toolchain/environment cache key; change when the environment changes")
    prepare.add_argument("--image-size", type=int, metavar="GIB", help="Store workspaces on separate APFS images with this capacity")
    create = commands.add_parser("create", help="Clone a prepared seed")
    create.add_argument("seed")
    create.add_argument("--name", default="")
    for action in ("mount", "unmount"):
        command = commands.add_parser(action, help="Mount an image workspace" if action == "mount" else "Unmount an image workspace")
        command.add_argument("id")
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
        store = None if args.action == "scan" else Store(args.root)
        if args.action == "scan":
            try:
                from ._scan import scan
            except ImportError as exc:
                raise StallionError("Install stallionfs first to build its native scanner: python3 -m pip install .") from exc
            result = scan(os.path.expanduser(args.path))
            text = (f"{result['files']} files, {result['directories']} directories, "
                    f"{result['symlinks']} symlinks, {result['other']} other entries\n"
                    f"{result['logical_bytes']} logical bytes; {result['skipped_mounts']} nested volumes skipped")
        elif args.action == "prepare":
            result = store.prepare(args.source, ref=args.ref, key=args.key, command=setup, image_size=args.image_size)
            text = result["id"]
        elif args.action == "create":
            result = store.create(args.seed, name=args.name)
            text = result["path"]
        elif args.action in ("mount", "unmount"):
            result = getattr(store, args.action)(args.id)
            text = result.get("path", result.get("unmounted"))
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
    except KeyboardInterrupt as exc:
        print("stallionfs: interrupted", file=sys.stderr)
        for note in getattr(exc, "__notes__", ()):
            print(note, file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
