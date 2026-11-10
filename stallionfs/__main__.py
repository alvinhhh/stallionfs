import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from . import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(prog="stallionfs", description="Filesystem tools for macOS")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--root", default=os.environ.get("STALLIONFS_HOME", str(Path.home() / "Library/Application Support/stallionfs")))
    parser.add_argument("--json", action="store_true", help="Print structured output")
    commands = parser.add_subparsers(dest="action", required=True)
    scan = commands.add_parser("scan", help="Count files and logical bytes using bulk metadata reads")
    scan.add_argument("path", help="Directory to scan; symlinks and nested volumes are not followed")
    scan.add_argument("--jobs", type=int, choices=range(1, 5), default=4, help="Directory workers; use 1 for lower CPU use")
    for action, help_text in (("clone", "Clone a file or directory to an exact new path"),
                              ("copy", "Copy a file or directory to an exact new path")):
        command = commands.add_parser(action, help=help_text)
        command.add_argument("source")
        command.add_argument("destination")
        command.add_argument("--jobs", type=int, choices=range(1, 5), default=4, help="Directory workers; use 1 for lower CPU use")
        if action == "copy":
            command.add_argument("--strategy", choices=("materialized", "auto"), default="materialized",
                                 help="Data transport; materialized by default")
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
    command_setup = commands.add_parser('command', help='Manage this user\'s sfs command link')
    command_setup.add_argument('operation', choices=('status', 'install', 'remove'))
    prepare = commands.add_parser("prepare", help="Prepare a clean commit once")
    prepare.add_argument("source")
    prepare.add_argument("--ref", default="HEAD")
    prepare.add_argument("--key", required=True, help="Toolchain/environment cache key; change when the environment changes")
    prepare.add_argument("--image-size", type=int, metavar="GIB", help="Store workspaces on separate APFS images with this capacity")
    native = commands.add_parser('register-native-image', help='Register an existing closed native image without moving it')
    native.add_argument('path')
    native.add_argument('--name', default='')
    create = commands.add_parser("create", help="Clone a prepared seed")
    create.add_argument("seed")
    create.add_argument("--name", default="")
    create.add_argument('--backend', choices=('native-image',), help='Use an owned native image with a mounted repository')
    create.add_argument('--capacity-gib', type=int, help='Required capacity for native images')
    create.add_argument('--native-profile', choices=('production', 'private-sfsro27'), default='production')
    create.add_argument('--native-host', type=Path, help='Qualified containing-app discovery executable')
    create.add_argument("--jobs", type=int, choices=range(1, 5), default=4, help="Folder clone workers; use 1 for lower CPU use")
    for action in ("mount", "unmount"):
        command = commands.add_parser(action, help="Mount an image workspace" if action == "mount" else "Unmount an image workspace")
        command.add_argument("id")
        if action == "unmount":
            command.add_argument("--continue", dest="continue_operation", metavar="OP", help="Withdraw an accepted mount before a retained snapshot/rollback")
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
    snapshot = commands.add_parser("snapshot", help="Capture a stopped managed workspace")
    snapshot.add_argument("id")
    snapshot.add_argument("--name", default="")
    snapshot.add_argument("--quiescent", action="store_true", help="Assert writers are stopped and flushed; allow a brief native unmount/remount")
    snapshot.add_argument("--continue", dest="continue_operation", metavar="OP", help="Continue the matching retained operation without repeating its mutation")
    snapshots = commands.add_parser("snapshots", help="List workspace snapshots")
    snapshots.add_argument("id")
    snapshots.add_argument("--operation", metavar="OP", help="Read retained phase and continuation instructions")
    rollback = commands.add_parser("rollback", help="Restore a snapshot and retain the previous workspace")
    rollback.add_argument("id")
    rollback.add_argument("snapshot")
    rollback.add_argument("--quiescent", action="store_true", help="Assert writers are stopped and flushed; allow a brief native unmount/remount")
    rollback.add_argument("--continue", dest="continue_operation", metavar="OP", help="Continue the matching retained operation without repeating its mutation")
    close = commands.add_parser("close", help="Record that all workspace writers have stopped")
    close.add_argument("id")
    close.add_argument("--quiescent", action="store_true")
    enroll = commands.add_parser("enroll", help="Enroll a workspace in cooperative cleanup")
    enroll.add_argument("id")
    enroll.add_argument("--disable", action="store_true")
    managed_run = commands.add_parser("run", help="Run a command while holding the managed-use lease")
    managed_run.add_argument("--auto-retire", action="store_true", help="Allow cooperative folder sessions to retire after seven observed idle days")
    managed_run.add_argument("id")
    managed_run.add_argument("command", nargs=argparse.REMAINDER)
    cleanup = commands.add_parser("cleanup", help="Preview or retire enrolled workspaces closed for seven days")
    cleanup_mode = cleanup.add_mutually_exclusive_group()
    cleanup_mode.add_argument("--enable", action="store_true")
    cleanup_mode.add_argument("--disable", action="store_true")
    cleanup_mode.add_argument("--apply", action="store_true")
    commands.add_parser("retained", help="List snapshots, rollback recovery, and protected trash")
    purge = commands.add_parser("purge", help="Preview or permanently delete retained data")
    purge.add_argument("kind", choices=("snapshots", "recovery", "trash"))
    purge.add_argument("id")
    purge.add_argument("--yes", action="store_true", help="Permanently delete selected data, including all snapshots inside a native image")
    commands.add_parser("doctor", help="Test native cloning and write isolation")
    from . import benchmark
    benchmark.parser(commands)
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
    if args.action == 'command':
        if any(value == '--root' or value.startswith('--root=') for value in raw[:command_index]):
            parser.error('--root applies to workspace commands')
        try:
            from ._command import run, describe
            result = run(args.operation)
            print(json.dumps(result, sort_keys=True) if args.json else describe(result))
            return 0
        except (OSError, ValueError, ImportError, KeyError, TypeError, KeyboardInterrupt, MemoryError) as error:
            interrupted = isinstance(error, KeyboardInterrupt)
            message = 'interrupted; inspect command status' if interrupted else str(error)
            print(json.dumps({'error': message}) if args.json else 'stallionfs: ' + message, file=sys.stderr)
            return 130 if interrupted else 1
    if args.action == 'benchmark':
        return benchmark.run(args)
    from .core import StallionError, Store, native_failure_details
    try:
        store = None if args.action in {"scan", "clone", "copy", "delete", "move", "volumes"} else Store(args.root)
        if args.action == "scan":
            try:
                from ._scan import scan
            except ImportError as exc:
                raise StallionError("Install stallionfs first to build its native scanner: python3 -m pip install .") from exc
            result = scan(os.path.expanduser(args.path), jobs=args.jobs)
            text = (f"{result['files']} files, {result['directories']} directories, "
                    f"{result['symlinks']} symlinks, {result['other']} other entries\n"
                    f"{result['logical_bytes']} logical bytes; {result['skipped_mounts']} nested volumes skipped")
        elif args.action in {"clone", "copy", "delete", "move", "volumes"}:
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
                if args.action == "copy":
                    _scan.copy(source, destination, jobs=args.jobs, strategy=args.strategy)
                elif args.action == "clone":
                    _scan.clone(source, destination, jobs=args.jobs)
                else:
                    _scan.move(source, destination, replace=args.replace, exchange=args.exchange)
                result, text = {"source": source, "destination": destination}, ""
                if args.action == "copy" and args.strategy == "auto":
                    result["strategy"] = "auto"
        elif args.action == 'register-native-image':
            result = store.register_native_image(args.path, name=args.name)
            text = result['id']
        elif args.action == "prepare":
            result = store.prepare(args.source, ref=args.ref, key=args.key, command=setup, image_size=args.image_size)
            text = result["id"]
        elif args.action == "create":
            options = {}
            if args.backend is not None or args.capacity_gib is not None or args.native_host is not None or args.native_profile != 'production':
                options = dict(backend=args.backend, capacity_gib=args.capacity_gib,
                               native_profile=args.native_profile, native_host=args.native_host)
            result = store.create(args.seed, name=args.name, jobs=args.jobs, **options)
            text = result["path"]
        elif args.action in ("mount", "unmount"):
            result = (store.continue_unmount(args.id, args.continue_operation)
                      if args.action == "unmount" and args.continue_operation is not None
                      else getattr(store, args.action)(args.id))
            text = result.get("path", result.get("unmounted"))
        elif args.action == "list":
            result = store.list(args.kind)
            text = "\n".join(f"{item['id']}\t{item.get('name', '')}\t{item['path']}" for item in result)
        elif args.action in ("remove", "restore"):
            result = store.move(args.id, restore=args.action == "restore")
            text = result["path"] if "path" in result else result["restored" if args.action == "restore" else "retired"]
        elif args.action == "gc":
            items = store.gc(older_than=args.older_than * 3600, yes=args.yes, jobs=args.jobs)
            result = {"deleted" if args.yes else "would_delete": items}
            text = json.dumps(result)
        elif args.action == "snapshot":
            result = store.snapshot(args.id, quiescent=args.quiescent, name=args.name,
                                    **({"continue_operation": args.continue_operation} if args.continue_operation is not None else {}))
            text = result["id"]
        elif args.action == "snapshots":
            result = store.snapshots(args.id, **({"operation_id": args.operation} if args.operation is not None else {}))
            if args.operation is not None:
                from ._native_recovery import format_compound_status
                text = format_compound_status(result)
            else:
                text = "\n".join(f"{item['id']}\t{item['name']}" for item in result)
        elif args.action == "rollback":
            result = store.rollback(args.id, args.snapshot, quiescent=args.quiescent,
                                    **({"continue_operation": args.continue_operation} if args.continue_operation is not None else {}))
            text = json.dumps(result)
        elif args.action == "close":
            result = store.close(args.id, quiescent=args.quiescent)
            text = args.id
        elif args.action == "enroll":
            result = store.enroll(args.id, enabled=not args.disable)
            text = args.id
        elif args.action == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            result = store.run(args.id, command, auto_retire=args.auto_retire)
            text = json.dumps(result) if args.json else ""
        elif args.action == "cleanup":
            if args.enable or args.disable:
                result = store.cleanup_config(enabled=args.enable)
            else:
                result = store.cleanup(apply=args.apply)
            text = json.dumps(result)
        elif args.action == "retained":
            result = store.retained()
            text = json.dumps(result)
        elif args.action == "purge":
            result = store.purge(args.kind, args.id, yes=args.yes)
            text = json.dumps(result)
        elif args.action == "forget":
            result = store.forget(args.seed, yes=args.yes)
            text = json.dumps(result)
        else:
            result = store.doctor()
            text = json.dumps(result, indent=2)
        if args.action in {"create", "mount", "unmount", "remove", "restore", "snapshot", "rollback", "close", "enroll", "run"}:
            store.opportunistic_cleanup()
        if args.json or text:
            print(json.dumps(result, sort_keys=True) if args.json else text)
        return result["returncode"] if args.action == "run" else 0
    except (StallionError, OSError, shutil.Error, KeyboardInterrupt, MemoryError, subprocess.TimeoutExpired) as exc:
        interrupted = isinstance(exc, KeyboardInterrupt)
        message = "interrupted" if interrupted else str(exc)
        notes = list(getattr(exc, "__notes__", ()))
        error = {"error": message}
        details = native_failure_details(exc)
        if details is None and 'result' in locals() and isinstance(result, dict):
            details = result.get('native_image_result')
        if details is not None:
            error['native_image_result'] = details
            from ._native_recovery import COMPOUND, compound_summary
            compound = details if details.get('operation') in COMPOUND else details.get('native_operation')
            if isinstance(compound, dict) and compound.get('operation') in COMPOUND:
                summary = compound_summary(compound)
                error['native_operation_summary'] = summary
                notes.append(summary['message'])
            elif interrupted or isinstance(exc, MemoryError):
                if details.get('committed'):
                    message = ('interrupted' if interrupted else 'response allocation failed') + '; the image change committed'
                elif details.get('outcome') == 'unknown':
                    message = ('interrupted' if interrupted else 'response allocation failed') + '; image publication outcome is unknown'
            elif isinstance(exc, OSError):
                if details.get('committed'):
                    message += '; the image change committed'
                elif details.get('outcome') == 'unknown':
                    message += '; image publication outcome is unknown'
            error['error'] = message
            if details.get('recovery') and (details.get('committed') or details.get('outcome') == 'unknown'):
                notes.append('Recovery snapshot name: ' + details['recovery'])
        if notes:
            error["notes"] = list(notes)
        print(json.dumps(error) if args.json else f"stallionfs: {message}", file=sys.stderr)
        if not args.json:
            for note in notes:
                print(note, file=sys.stderr)
        return 130 if interrupted else 1


if __name__ == "__main__":
    sys.exit(main())
