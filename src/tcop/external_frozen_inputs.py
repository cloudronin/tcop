"""Read-only input snapshot and unsealed-output writer for amendment 005."""
from hashlib import sha256
from pathlib import Path
import re

from .external_foundation_seals import digest,require,write_seal,read_seal
from .external_trace_validation import PINNED_TOOLS_SHA256

CATEGORIES={'spec_modules','trace_checker','converter','trace_schema','tlc_configs'}


def default_paths():
    return {'spec_modules':[p for p in sorted(Path('formal/tla').glob('*.tla')) if p.name!='TCOPTrace.tla'],
        'trace_checker':[Path('formal/tla/TCOPTrace.tla')],'converter':[Path('formal/trace_to_tla.py')],
        'trace_schema':[Path('formal/trace-v1.schema.json')],'tlc_configs':sorted(Path('formal/tla').glob('*.cfg'))}


def build_inputs(paths=None,bounds=None):
    paths=paths if paths is not None else default_paths()
    require(set(paths)==CATEGORIES and all(isinstance(v,list) and v for v in paths.values()),'every frozen input category must be nonempty')
    hashes={};numeric_bounds={}
    for category,members in paths.items():
        hashes[category]={}
        for member in members:
            p=Path(member);require(p.is_file() and not p.is_symlink(),'missing or linked frozen source')
            raw=p.read_bytes();hashes[category][str(p)]=sha256(raw).hexdigest()
            if category=='tlc_configs':
                for name,value in re.findall(r'^\s+(\w+)\s*=\s*(\d+)\s*$',raw.decode(),re.M):numeric_bounds[str(p)+':'+name]=int(value)
    tools=Path('formal/pinned-tools.json')
    require(sha256(tools.read_bytes()).hexdigest()==PINNED_TOOLS_SHA256,'pinned-tools record differs from 005 seal')
    bounds=numeric_bounds if bounds is None else bounds
    require(isinstance(bounds,dict) and bool(bounds) and all(type(v) is int and v>=0 for v in bounds.values()),'explicit/configuration numeric bounds required')
    return {'schema':'tcop.external-frozen-inputs/1.0','inputs':hashes,'bounds':bounds,'pinned_tools_record_sha256':PINNED_TOOLS_SHA256}


def freeze_inputs(output,*,paths=None,bounds=None,first_live_at=None):
    require(first_live_at is None,'cannot revise/freeze model inputs after any live episode')
    require(not Path(output).resolve().is_relative_to(Path('formal').resolve()),'frozen-input output must be outside the read-only formal tree')
    body=build_inputs(paths,bounds)
    require(body==build_inputs(paths,bounds),'input changed while being frozen')
    write_seal(Path(output),'frozen-inputs',{'record.json':body})
    return verify_inputs(output)


def verify_inputs(root,*,check_current_inputs=True):
    value=read_seal(Path(root),'frozen-inputs');body=value['documents']['record.json']
    require(body['schema']=='tcop.external-frozen-inputs/1.0','unknown frozen-input schema')
    if check_current_inputs:
        require(body==build_inputs({k:[Path(p) for p in v] for k,v in body['inputs'].items()},body['bounds']),'frozen model/config/converter/schema changed')
    return {'valid':True,'body':body,'sha256':digest(body),'sealed_at':value['seal']['sealed_at']}
