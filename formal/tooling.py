"""Shared, stdlib-only tool verification and result metadata."""
from pathlib import Path
import hashlib
import json
import re
import subprocess

FORMAL = Path(__file__).resolve().parent
JAVA = '/opt/homebrew/opt/openjdk/bin/java'


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def java_properties():
    run = subprocess.run([JAVA, '-XshowSettings:properties', '-version'],
                         capture_output=True, text=True, check=True)
    output = run.stdout + run.stderr
    props = dict(re.findall(r'^    ([\w.]+) = (.*)$', output, re.M))
    return props, output


def checked_tools():
    path = FORMAL / 'pinned-tools.json'
    record = json.loads(path.read_text())
    jar = FORMAL / 'tools' / record['tla_plus']['file']
    if sha256(jar) != record['tla_plus']['sha256'] or jar.stat().st_size != record['tla_plus']['size_bytes']:
        raise RuntimeError('Pinned TLC jar mismatch')
    props, _ = java_properties()
    for key, value in record['jdk']['observed_properties'].items():
        if props.get(key) != value:
            raise RuntimeError(f'Pinned JDK mismatch for {key}: {props.get(key)!r}')
    return sha256(path)


def tlc_stats(output):
    counts = re.findall(r'(?m)^(\d+) states generated, (\d+) distinct states found(?:, (\d+) states left on queue)?\.', output)
    levels = re.findall(r'Starting level (\d+):', output)
    depth = re.findall(r'depth of the complete state graph search is (\d+)', output)
    return dict(generated=int(counts[-1][0]) if counts else None,
                distinct=int(counts[-1][1]) if counts else None,
                queue_remaining=int(counts[-1][2]) if counts and counts[-1][2] else None,
                depth=int(depth[-1]) if depth else int(levels[-1]) if levels else None,
                depth_kind='bfs_graph_depth' if depth else 'dfid_search_level')
