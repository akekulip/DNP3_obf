"""One-time, reversible path migration; never a supported build/run entry point."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
ANCHOR = '63833e020d7d515bf4ed3ca1b01ed0ed6c7e330c'
OLD = ('defense4','history','relay_rto_20260915','tools','slides ','.scratch_p4',
       '.scratch_repo','.drawio-tmp','.superpowers','zlog-cfg-cur','bf_drivers.log',
       'model_20261006_125053.log','FINAL_TIMING_ALLOWLIST.txt')
OUT = ROOT/'results/analysis/archive_inventory.jsonl'

def git(*args):
    return subprocess.check_output(['git',*args],cwd=ROOT)

def selected(path):
    return any(path == name or path.startswith(name+'/') for name in OLD)

def files():
    for name in OLD:
        path=ROOT/name
        if path.is_dir() and not path.is_symlink():
            for parent,dirs,names in os.walk(path):
                for n in names:
                    yield Path(parent)/n
                for n in dirs[:]:
                    q=Path(parent)/n
                    if q.is_symlink():
                        yield q
                        dirs.remove(n)
        elif path.exists() or path.is_symlink():
            yield path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    tracked={}
    for item in git('ls-tree','-r','-z',ANCHOR).split(b'\0'):
        if not item:continue
        info,name=item.split(b'\t',1)
        mode,kind,blob=info.decode().split()
        name=os.fsdecode(name)
        if selected(name):tracked[name]=(mode,blob)
    untracked=set(os.fsdecode(x) for x in git('ls-files','--others','--exclude-standard','-z').split(b'\0') if x)
    modified=set(os.fsdecode(x) for x in git('diff','--name-only','--no-renames','--diff-filter=M',ANCHOR,'-z','--',*OLD).split(b'\0') if x)
    rows=[]
    for source in files():
        name=str(source.relative_to(ROOT)); st=source.lstat()
        status='tracked' if name in tracked else ('untracked' if name in untracked else 'ignored')
        destination=ROOT/('Archive/tracked/original' if status=='tracked' else 'Archive/local/original')/name
        row={'source':name,'destination':str(destination.relative_to(ROOT)),
             'original_status':status,'bytes':st.st_size,'inode':st.st_ino,'mode':st.st_mode,
             'anchor_blob':tracked.get(name,(None,None))[1], 'working_copy_modified':name in modified}
        rows.append(row)
    OUT.write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows))
    print(json.dumps({'files':len(rows),'bytes':sum(r['bytes'] for r in rows),
                      'tracked':sum(r['original_status']=='tracked' for r in rows),'apply':args.apply}),flush=True)
    if not args.apply:return
    assert all(not (ROOT/r['destination']).exists() for r in rows), 'archive target already exists'
    for row in rows:
        if row['original_status'] != 'tracked':continue
        source,destination=ROOT/row['source'],ROOT/row['destination']
        destination.parent.mkdir(parents=True,exist_ok=True)
        if row['working_copy_modified']:
            working=ROOT/'Archive/local/migration_working_copies'/row['source']
            working.parent.mkdir(parents=True,exist_ok=True)
            os.replace(source,working)
            destination.write_bytes(git('cat-file','blob',row['anchor_blob']))
            os.chmod(destination,row['mode'])
            row['preserved_working_copy']=str(working.relative_to(ROOT))
        else:
            os.replace(source,destination)
            assert destination.lstat().st_ino==row['inode']
        row['moved']=True
    # Remaining unique local/ignored artifacts move as intact directories.
    for name in OLD:
        source=ROOT/name
        if not source.exists() and not source.is_symlink():continue
        destination=ROOT/'Archive/local/original'/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        os.replace(source,destination)
    for row in rows:
        target=ROOT/row['destination']
        assert target.exists() or target.is_symlink(),row
        if not row['working_copy_modified']:
            assert target.lstat().st_ino==row['inode'] and target.lstat().st_size==row['bytes'],row
        row['moved']=True
    OUT.write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows))
    print('verified every destination; unique bytes preserved; historical tree detached',flush=True)

if __name__=='__main__':main()
