"""Freeze independent steering sources and preregister A2/A3; no production edits."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def identity(root):
    h = hashlib.sha256()
    for p in sorted(root.rglob('*')):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode()+b'\0'+hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def prepare(repo, output):
    repo, output = repo.resolve(), output.resolve()
    paths = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z', '--cached', '--others', '--exclude-standard']).decode().split('\0')
    output.mkdir(parents=True, exist_ok=False)
    base = output/'sources'/'baseline'; base.mkdir(parents=True)
    for name in sorted(set(filter(None, paths))):
        src = repo/name
        if not src.is_file(): continue
        if not src.resolve().is_relative_to(repo): raise ValueError('source escapes repository: '+name)
        dst = base/name; dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, dst)
    patches = repo/'bench/experiments/steering'
    variants = [('flat-hints', 'baseline', 'reply-hints'),
                ('hierarchical', 'flat-hints', 'hierarchical-admission'),
                ('hierarchical-napi', 'hierarchical', 'flows-napi')]
    patch_ids, changed_sources = {}, {}
    for name, parent, patch in variants:
        dst = base.parent/name; shutil.copytree(base.parent/parent, dst)
        path = patches/(patch+'.patch')
        patch_ids[patch] = hashlib.sha256(path.read_bytes()).hexdigest()
        result = subprocess.run(['patch', '-p1', '--batch', '--forward', '-i', str(path)], cwd=dst,
                                capture_output=True, text=True)
        (output/(name+'.patch.log')).write_text(result.stdout+result.stderr)
        if result.returncode: raise RuntimeError('isolated patch failed: '+name)
        changed = [p.relative_to(dst).as_posix() for p in sorted((dst/'src').rglob('*'))
                   if p.is_file() and p.read_bytes() != (base.parent/parent/p.relative_to(dst)).read_bytes()]
        expected = ['src/tun.c', 'src/tun_steering.h'] if name == 'flat-hints' else [
            'src/tun_steering.h' if name == 'hierarchical' else 'src/tun.c']
        if changed != expected:
            raise RuntimeError(f'ablation changed unexpected production sources: {changed}')
        changed_sources[name] = changed
        if (dst/'src/tayga.c').read_bytes() != (base/'src/tayga.c').read_bytes():
            raise RuntimeError('ablation unexpectedly includes worker affinity')
    harness = output/'harness'; shutil.copytree(base, harness)
    sources = {p.name: dict(path=str(p), identity=identity(p)) for p in sorted(base.parent.iterdir())}
    design = dict(schema_version=1, purpose='diagnostic-only', product_accepted=False,
        hypothesis='Isolate cold admission and TUN NAPI, preserving reply hints and worker policy.',
        sources=sources, harness=dict(path=str(harness), identity=identity(harness)), patches=patch_ids,
        changed_production_sources=changed_sources,
        pairs=[dict(pair=i, order=['baseline', 'candidate'] if i%2 else ['candidate', 'baseline'],
                    client_port_base=40000+i*100) for i in range(1, 6)],
        workload=dict(clients=4, flows=1, workers=3, duration=20, warmup=5,
                      rate=0, protocol='tcp', offload='auto', offlink_mtu=1280, endpoint_affinity='off'),
        comparisons=[dict(name='A2', baseline='flat-hints', candidate='hierarchical', variable='admission'),
                     dict(name='A3', baseline='hierarchical', candidate='hierarchical-napi', variable='NAPI')],
        decision='Retain every failed/invalid session. Diagnostic results never authorize production promotion.',
        source_revision=subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip())
    (output/'design.json').write_text(json.dumps(design, indent=2)+'\n')
    (output/'working-tree.patch').write_bytes(subprocess.check_output(['git', '-C', str(repo), 'diff', '--binary']))
    return design


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(prepare(a.repo, a.output), indent=2))


if __name__ == '__main__': main()
