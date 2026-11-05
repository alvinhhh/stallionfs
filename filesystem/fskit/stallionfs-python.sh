#!/bin/sh
unset ENV BASH_ENV CDPATH
case "$0" in
    /*/Contents/Resources/Runtime/CLI/bin/stallionfs-python) ;;
    *) printf '%s\n' 'stallionfs: use the absolute bundled Python helper' >&2; exit 1 ;;
esac
case "$0" in
    *'/../'*|*'/./'*|*'//'*) printf '%s\n' 'stallionfs: invalid bundled helper path' >&2; exit 1 ;;
esac
if [ -L "$0" ]; then
    printf '%s\n' 'stallionfs: bundled helper must not be a symlink' >&2
    exit 1
fi
script_dir=${0%/*}
exec "$script_dir/../../CPython/bin/python3.13" -I -B -S \
    "$script_dir/../lib/python3.13/site-packages/stallionfs/_bundle.py" "$0" "$@"
