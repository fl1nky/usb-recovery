"""Create owned regular FAT images with dosfstools/mtools, without mounting.

Run on a disposable Linux CI runner. Originals and hashes come from this
producer, not from the recovery implementation under test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from native_storage import digest, validate


def produce(destination):
    if destination.exists():
        raise ValueError('OUTPUT_EXISTS')
    destination.mkdir(parents=True)
    environment = {**os.environ, 'LC_ALL': 'C.UTF-8', 'MTOOLSRC': '/dev/null'}
    tools = {}
    commands = []

    def execute(name, *args, check=True):
        executable = shutil.which(name)
        if executable is None:
            raise ValueError('MISSING_NATIVE_TOOL_' + name)
        result = subprocess.run([executable, *map(str, args)], capture_output=True, env=environment, timeout=60)
        commands.append({'tool': name, 'arguments': list(map(str, args)), 'exit': result.returncode})
        if check and result.returncode:
            raise RuntimeError(name + ': ' + result.stderr.decode('utf-8', errors='replace')[:500])
        return result

    for name in ('mkfs.fat', 'mcopy', 'mdel', 'mtype', 'mshowfat', 'mmd'):
        tool = shutil.which(name)
        if tool is None:
            raise ValueError('MISSING_NATIVE_TOOL_' + name)
        version = execute(name, '--version', check=False)
        tools[name] = {'executable_sha256': digest(Path(tool)),
                       'version': (version.stdout + version.stderr).decode('utf-8', errors='replace').splitlines()[0]}

    cases = []

    def record(image, name, expected, kind, mapping=''):
        cases.append({'name': name, 'engine': 'fat', 'image': image.name,
                      'bytes': image.stat().st_size, 'sha256': digest(image),
                      'expected_sha256': expected,
                      'truth_scope': 'target_contents_only' if expected else 'complete_negative',
                      'provenance': {'kind': kind, 'tools': tools, 'native_mapping_before_deletion': mapping,
                                     'note': 'Owned payload; native mcopy/mtype round trip before mdel; no mount or physical device.'}})

    with tempfile.TemporaryDirectory(prefix='owned-native-fat-') as temp:
        private = Path(temp)
        for bits, mib in ((12, 4), (16, 16), (32, 64)):
            label = 'fat%d' % bits
            base = private / (label + '.dd')
            with base.open('xb') as stream:
                stream.truncate(mib * 1024 * 1024)
            execute('mkfs.fat', '-F', bits, '-n', 'OWNEDBENCH', base)
            raw = (('Owned native %s recipe; начинка; no personal data.\n' % label).encode('utf-8') * 1024)
            payload = private / 'recipe.bin'
            payload.write_bytes(raw)
            target_hash = hashlib.sha256(raw).hexdigest()
            execute('mcopy', '-i', base, payload, '::recipe.bin')
            assert execute('mtype', '-i', base, '::recipe.bin').stdout == raw
            mapping = execute('mshowfat', '-i', base, '::recipe.bin').stdout.decode('utf-8', errors='strict')

            live = destination / (label + '-allocated.dd')
            shutil.copyfile(base, live)
            record(live, label + '-allocated', [], 'native_allocated_file_negative_control', mapping)

            deleted = destination / (label + '-deleted.dd')
            shutil.copyfile(base, deleted)
            execute('mdel', '-i', deleted, '::recipe.bin')
            assert execute('mtype', '-i', deleted, '::recipe.bin', check=False).returncode != 0
            record(deleted, label + '-deleted', [target_hash], 'native_tool_deletion', mapping)

            nested = destination / (label + '-unicode-directory.dd')
            shutil.copyfile(base, nested)
            execute('mmd', '-i', nested, '::ARCHIVE')
            text = ('Owned %s nested рецепт; UTF-8 content.\n' % label).encode('utf-8') * 513
            payload.write_bytes(text)
            name = '::ARCHIVE/длинный рецепт.bin'
            execute('mcopy', '-i', nested, payload, name)
            assert execute('mtype', '-i', nested, name).stdout == text
            nested_map = execute('mshowfat', '-i', nested, name).stdout.decode('utf-8', errors='strict')
            execute('mdel', '-i', nested, name)
            record(nested, label + '-unicode-directory', [hashlib.sha256(text).hexdigest()],
                   'native_tool_deletion', nested_map)

    empty = destination / 'no-filesystem.dd'
    with empty.open('xb') as stream:
        stream.truncate(4 * 1024 * 1024)
    record(empty, 'no-filesystem', [], 'owned_zero_negative_control')
    manifest = {'schema': 1, 'producer_sha256': digest(Path(__file__)), 'cases': cases}
    (destination / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (destination / 'producer-commands.json').write_text(json.dumps(commands, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    validate(destination)
    print('Prepared %d native-tool FAT controls; regular files only.' % len(cases))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--destination', type=Path, required=True)
    produce(parser.parse_args().destination.resolve())
