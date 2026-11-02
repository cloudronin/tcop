#!/bin/sh
set -eu
formal_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 -B "$formal_dir/check_trace_fixtures.py" "$@"
