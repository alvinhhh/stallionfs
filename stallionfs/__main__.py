import argparse
import json
import os
from pathlib import Path
import shutil
import sys

from . import __version__
from .core import StallionError, Store


def main(argv=None):
    parser = argparse.ArgumentParser(prog="stallionfs", description="Filesystem tools for macOS")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--root", default=os.environ.get("STALLIONFS_HOME", str(Path.home() / "Library/Application Support/stallionfs")))
    parser.add_argument("--json", action="store_true", help="Print structured output")
    commands = parser.add_subparsers(dest="action", required=True)
    scan = commands.add_parser("scan", help="Count files and logical bytes using bulk metadata reads")
    scan.add_argument("path", help="Directory to scan; symlinks and nested volumes are not followed")
    scan.add_argument("--jobs", type=int, choices=range(1, 5), default=4, help="Directory workers; use 1 for lower CPU use")
    clone = commands.add_parser("clone", help="Clone a file or directory to an exact new path")
    clone.add_argument("source")
    clone.add_argument("destination")
    clone.add_argument("--jobs", type=int, choices=range(1, 5), default=4, help="Directory workers; use 1 for lower CPU use")
    delete = commands.add_parser("delete", help="Permanently delete a file or directory without following links")
    delete.add_argument("path")
    delete.add_argument("-r", "--recursive", action="store_true")
    delete.add_argument("--missing-ok", action="store_true")
    delete.add_argument("--jobs", type=int, choices=range(1, 5), default=4, help="Directory workers; use 1 for lower CPU use")
    move = commands.add_parser("move", help="Move to an exact path on the same volume, without overwriting")
    move.add_argument("source")
    move.add_argument("destination")
    move_mode = move.add_mutually_exclusive_group()
    move_mode.add_argument("--replace", action="store_true", help="Replace the destination atomically")
    move_mode.add_argument("--exchange", action="store_true", help="Swap two existing paths atomically")
    commands.add_parser("volumes", help="List mounted filesystems")
    prepare = commands.add_parser("prepare", help="Prepare a clean commit once")
    prepare.add_argument("source")
    prepare.add_argument("--ref", default="HEAD")
    prepare.add_argument("--key", required=True, help="Toolchain/environment cache key; change when the environment changes")
    prepare.add_argument("--image-size", type=int, metavar="GIB", help="Store workspaces on separate APFS images with this capacity")
    create = commands.add_parser("create", help="Clone a prepared seed")
    create.add_argument("seed")
    create.add_argument("--name", default="")
    create.add_argument("--jobs", type=int, choices=range(1, 5), default=4, help="Folder clone workers; use 1 for lower CPU use")
    for action in ("mount", "unmount"):
        command = commands.add_parser(action, help="Mount an image workspace" if action == "mount" else "Unmount an image workspace")
        command.add_argument("id")
    listing = commands.add_parser("list", help="List stored workspaces, seeds or trash")
    listing.add_argument("kind", nargs="?", choices=["workspaces", "seeds", "trash"], default="workspaces")
    for action in ("remove", "restore"):
        command = commands.add_parser(action, help="Move a workspace to trash" if action == "remove" else "Restore a trashed workspace")
        command.add_argument("id")
    gc = commands.add_parser("gc", help="Preview or permanently delete eligible trash")
    gc.add_argument("--jobs", type=int, choices=range(1, 5), default=4, help="Deletion workers; use 1 for lower CPU use")
    gc.add_argument("--yes", action="store_true", help="Permanently delete the listed trash")
    gc.add_argument("--older-than", type=float, default=24, metavar="HOURS")
    forget = commands.add_parser("forget", help="Preview or delete a regenerable seed")
    forget.add_argument("seed")
    forget.add_argument("--yes", action="store_true")
    commands.add_parser("doctor", help="Test native cloning and write isolation")
    raw = list(sys.argv[1:] if argv is None else argv)
    setup = []
    command_index = 0
    while command_index < len(raw):
        option = raw[command_index]
        if option == "--root":
            command_index += 2
        elif option == "--json" or option.startswith("--root="):
            command_index += 1
        else:
            break
    if (command_index < len(raw) and raw[command_index] == "prepare"
            and "--" in raw[command_index + 1:]):
        index = raw.index("--", command_index + 1)
        raw, setup = raw[:index], raw[index + 1:]
    args = parser.parse_args(raw)
    if setup and args.action != "prepare":
        parser.error("Only prepare accepts a command after --")
    try:
        store = None if args.action in {"scan", "clone", "delete", "move", "volumes"} else Store(args.root)
        if args.action == "scan":
            try:
                from ._scan import scan
            except ImportError as exc:
                raise StallionError("Install stallionfs first to build its native scanner: python3 -m pip install .") from exc
            result = scan(os.path.expanduser(args.path), jobs=args.jobs)
            text = (f"{result['files']} files, {result['directories']} directories, "
                    f"{result['symlinks']} symlinks, {result['other']} other entries\n"
                    f"{result['logical_bytes']} logical bytes; {result['skipped_mounts']} nested volumes skipped")
        elif args.action in {"clone", "delete", "move", "volumes"}:
            from . import _scan
            if args.action == "volumes":
                result = _scan.mounts()
                text = "\n".join(f"{row['filesystem']}\t{'read-only' if row['readonly'] else 'writable'}\t{row['path']}" for row in result)
            elif args.action == "delete":
                path = args.path
                _scan.delete(path, recursive=args.recursive, missing_ok=args.missing_ok, jobs=args.jobs)
                result, text = {"path": path}, ""
            else:
                source, destination = args.source, args.destination
                if args.action == "clone":
                    _scan.clone(source, destination, jobs=args.jobs)
                else:
                    _scan.move(source, destination, replace=args.replace, exchange=args.exchange)
                result, text = {"source": source, "destination": destination}, ""
        elif args.action == "prepare":
            result = store.prepare(args.source, ref=args.ref, key=args.key, command=setup, image_size=args.image_size)
            text = result["id"]
        elif args.action == "create":
            result = store.create(args.seed, name=args.name, jobs=args.jobs)
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
            items = store.gc(older_than=args.older_than * 3600, yes=args.yes, jobs=args.jobs)
            result = {"deleted" if args.yes else "would_delete": items}
            text = json.dumps(result)
        elif args.action == "forget":
            result = store.forget(args.seed, yes=args.yes)
            text = json.dumps(result)
        else:
            result = store.doctor()
            text = json.dumps(result, indent=2)
        if args.json or text:
            print(json.dumps(result, sort_keys=True) if args.json else text)
        return 0
    except (StallionError, OSError, shutil.Error, KeyboardInterrupt) as exc:
        interrupted = isinstance(exc, KeyboardInterrupt)
        message = "interrupted" if interrupted else str(exc)
        notes = getattr(exc, "__notes__", ())
        error = {"error": message}
        if notes:
            error["notes"] = list(notes)
        print(json.dumps(error) if args.json else f"stallionfs: {message}", file=sys.stderr)
        if not args.json:
            for note in notes:
                print(note, file=sys.stderr)
        return 130 if interrupted else 1


if __name__ == "__main__":
    sys.exit(main())
