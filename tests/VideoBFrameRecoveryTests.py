"""Pinned native B-frame fMP4 oracle and isolated public-engine source test.

No helper, application, package or real-device acceptance is performed here.
The fixture writer uses only FFmpeg and a box reader, never recovery code.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

from build_fmp4_media_fixtures import boxes, child, full

ROOT = Path(__file__).resolve().parents[1]
FF_SHA = '3256173f3f8bffd7df12227c68adf68025edb1832273a9530688a7bb1ed8edec'
FP_SHA = 'f0d36ecbbdd3bcfac3efa078c96c7271c2e68b3810595552ac3b7f17e9a65c52'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(argv, log):
    proc = subprocess.run([str(x) for x in argv], capture_output=True, timeout=90,
                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    log.append(dict(argv=[str(x) for x in argv], native_exit=proc.returncode,
                    stdout=proc.stdout.decode('utf-8', 'replace'),
                    stderr=proc.stderr.decode('utf-8', 'replace')))
    assert proc.returncode == 0, log[-1]
    return proc.stdout


def frames(ff, path, log):
    raw = run([ff, '-v', 'error', '-nostdin', '-i', path, '-map', '0:v:0', '-an', '-f', 'framemd5', '-'], log)
    result = b'\n'.join(line for line in raw.splitlines() if line and not line.startswith(b'#'))
    assert len(result.splitlines()) == 12
    return result


def fixtures(destination, ff, log):
    fp = ff.with_name('ffprobe.exe')
    assert sha(ff.read_bytes()) == FF_SHA and sha(fp.read_bytes()) == FP_SHA
    cases = []
    for name, signed in [('unsigned', False), ('signed', True)]:
        path = destination / (name + '.mp4')
        run([ff, '-v', 'error', '-nostdin', '-n', '-f', 'lavfi', '-i', 'testsrc2=size=160x96:rate=6',
             '-frames:v', '12', '-an', '-map_metadata', '-1', '-fflags', '+bitexact', '-flags:v', '+bitexact',
             '-c:v', 'libx264', '-threads', '1', '-preset', 'medium', '-crf', '24', '-g', '4',
             '-keyint_min', '4', '-sc_threshold', '0', '-bf', '2', '-movflags',
             '+empty_moov+default_base_moof+frag_keyframe' + ('+negative_cts_offsets' if signed else ''), path], log)
        raw = path.read_bytes()
        top = boxes(raw)
        assert [b['kind'] for b in top] == ['ftyp', 'moov', 'moof', 'mdat', 'moof', 'mdat', 'moof', 'mdat', 'mfra']
        packets = json.loads(run([fp, '-v', 'error', '-select_streams', 'v:0', '-show_packets',
                                 '-show_data_hash', 'sha256', '-of', 'json', path], log))['packets']
        assert len(packets) == 12 and any(int(p['pts']) != int(p['dts']) for p in packets)
        offsets = [int(p['pts']) - int(p['dts']) for p in packets]
        assert min(offsets) >= 0 and max(offsets) > 0
        raw_offsets = []
        for n in (2, 4, 6):
            trun = child(raw, child(raw, top[n], 'traf'), 'trun')
            version, flags = full(raw, trun)
            assert version == int(signed) and flags & 0x800
            at = trun['data'] + 12 + (4 if flags & 4 else 0)
            count = int.from_bytes(raw[trun['data']+4:trun['data']+8], 'big')
            for _ in range(count):
                at += 4 * sum(bool(flags & bit) for bit in (0x100, 0x200, 0x400))
                raw_offsets.append(struct.unpack_from('>i' if signed else '>I', raw, at)[0])
                at += 4
            assert at == trun['end']
        assert min(raw_offsets) < 0 if signed else min(raw_offsets) >= 0 and max(raw_offsets) > 0
        locations = [32768, 1048576, 1572864, 262144, 786432, 1966080]
        ranges = [(top[0]['offset'], top[0]['end']), (top[1]['offset'], top[1]['end'])]
        ranges += [(top[n]['offset'], top[n + 1]['end']) for n in (2, 4, 6)]
        ranges += [(top[-1]['offset'], top[-1]['end'])]
        image, extents = bytearray(b'\xa7' * (2 * 1024 * 1024)), []
        for (low, high), physical in zip(ranges, locations):
            image[physical:physical + high-low] = raw[low:high]
            extents.append(dict(ImageOffset=physical, LogicalOffset=low, Length=high-low))
        source = destination / (name + '.dd')
        source.write_bytes(image)
        oracle = frames(ff, path, log)
        (destination / (name + '.framemd5')).write_bytes(oracle)
        cases.append(dict(Name=name, Original=str(path), Image=str(source), Sha256=sha(raw),
                          SourceSha256=sha(image), FrameSha256=sha(oracle), Extents=extents))
    return cases


def compile_engine(destination, log, baseline=False):
    engines = ROOT / 'src/Recovery/Recovery/Engines'
    sources = sorted([*engines.glob('FragmentedMediaRecovery*.cs'), engines/'Fmp4Recovery.cs',
                      engines/'AacLcValidator.cs', engines/'AacSyntaxTables.cs', engines/'HevcSampleValidator.cs'])
    if baseline:
        target = destination / 'baseline-sources'
        target.mkdir()
        copied = []
        for source in sources:
            original = run(['git', '-C', ROOT, 'show', '5684800:' + source.relative_to(ROOT).as_posix()], log)
            path = target / source.name
            path.write_bytes(original)
            copied.append(path)
        sources = copied
    compiler = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    library = destination / ('baseline.dll' if baseline else 'current.dll')
    run([compiler, '/nologo', '/target:library', '/platform:x64', '/optimize+', '/warnaserror+',
         '/reference:System.Web.Extensions.dll', '/out:' + str(library), *sources], log)
    harness = destination / ('baseline-run.cs' if baseline else 'current-run.cs')
    harness.write_text('using System;using System.IO;using System.Threading;using UsbRecovery;'
                       'class Run{static void Main(string[] a){try{Console.WriteLine(FragmentedMediaRecovery.Recover(a[0],a[1],CancellationToken.None,null));}'
                       'catch(IOException e){Console.WriteLine(e.Message);}}}', encoding='utf-8')
    binary = harness.with_suffix('.exe')
    run([compiler, '/nologo', '/platform:x64', '/reference:' + str(library), '/out:' + str(binary), harness], log)
    return binary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--ffmpeg', type=Path, required=True)
    args = parser.parse_args()
    destination = args.destination.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    log, results = [], []
    try:
        cases = fixtures(destination, args.ffmpeg.resolve(), log)
        baseline = compile_engine(destination, log, True)
        current = compile_engine(destination, log)
        for case in cases:
            before = Path(case['Image']).read_bytes()
            for label, executable, expected in [('baseline', baseline, 0), ('current', current, 1)]:
                output = destination / (case['Name'] + '-' + label)
                run([executable, case['Image'], output], log)
                report = json.loads((output/'fragmented-media.json').read_text(encoding='utf-8-sig'))
                assert len(report['Files']) == expected
                assert Path(case['Image']).read_bytes() == before
                if expected:
                    record = report['Files'][0]
                    recovered = output / record['Path']
                    assert recovered.read_bytes() == Path(case['Original']).read_bytes()
                    assert [{key: e[key] for key in ('ImageOffset','LogicalOffset','Length')}
                            for e in record['Extents']] == case['Extents']
                    assert sha(frames(args.ffmpeg, recovered, log)) == case['FrameSha256']
                    assert not record['PayloadAuthenticated'] and not record['DeletionConfirmed']
                results.append(dict(case=case['Name'], version=label, recovered=expected,
                                    skipped=report['Skipped'], status=report['Status']))
            # Independent identical-source and missing-fragment controls.
            for label in ('identical-alias', 'missing', 'distinct-compatible'):
                image = bytearray(before)
                extent = case['Extents'][2]
                at, length = extent['ImageOffset'], extent['Length']
                if label == 'missing':
                    image[at:at+length] = b'\xa7' * length
                else:
                    image[65536:65536+length] = image[at:at+length]
                    if label == 'distinct-compatible':
                        image[65536+length-8] ^= 1
                source = destination / (case['Name']+'-'+label+'.dd')
                source.write_bytes(image)
                output = destination / (case['Name']+'-'+label)
                run([current, source, output], log)
                report = json.loads((output/'fragmented-media.json').read_text(encoding='utf-8-sig'))
                assert source.read_bytes() == image
                assert len(report['Files']) == (1 if label == 'identical-alias' else 0)
                if label == 'identical-alias':
                    assert len(report['Files'][0]['AlternateExtents']) == 1
                    assert (output/report['Files'][0]['Path']).read_bytes() == Path(case['Original']).read_bytes()
                elif label == 'distinct-compatible':
                    assert report['Skipped'].get('fmp4_payload_ambiguous') == 1
                else:
                    assert report['Status'] == 'partial'
                results.append(dict(case=case['Name'], control=label, status=report['Status'],
                                    recovered=len(report['Files'])))
        print('PASS: two native B-frame layouts baseline0/current1, exact bytes/maps/12 decoded frames, six damage/alias controls')
    finally:
        (destination/'native-log.json').write_text(json.dumps(log, indent=2)+'\n', encoding='utf-8')
        (destination/'results.json').write_text(json.dumps(results, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
