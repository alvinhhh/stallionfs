"""Run a fixed installed collector with explicit package and resource roots."""
from pathlib import Path
import runpy
import sys


def main():
    if not all((sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode)):
        raise RuntimeError('Installed collectors require isolated Python without site initialization')
    package = Path(__file__).resolve(strict=True).parent
    standard_paths = list(sys.path)
    sys.path.append(str(package.parent))
    import stallionfs
    if Path(stallionfs.__file__).resolve(strict=True) != package / '__init__.py':
        raise RuntimeError('Installed collector package origin changed')
    from stallionfs.benchmark import COLLECTORS, _resources
    if len(sys.argv) < 2 or sys.argv[1] not in COLLECTORS:
        raise ValueError('Unknown installed benchmark collector')
    name = sys.argv[1]
    resources = _resources()
    # Standard modules stay first; verified collectors precede unrelated site siblings.
    sys.path[:] = [*standard_paths, str(resources), str(package.parent)]
    script = resources / name
    sys.argv[:] = [str(script), *sys.argv[2:]]
    runpy.run_path(str(script), run_name='__main__')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
