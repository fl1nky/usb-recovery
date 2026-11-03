"""Independent pinned FFmpeg/ffprobe native fMP4 witness writer; no recovery imports."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import time
import argparse

HERE = FF = FP = None
FF_SHA = '3256173f3f8bffd7df12227c68adf68025edb1832273a9530688a7bb1ed8edec'
FP_SHA = 'f0d36ecbbdd3bcfac3efa078c96c7271c2e68b3810595552ac3b7f17e9a65c52'
COMMANDS = []

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')

def run(args):
    start = time.monotonic()
    p = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=90, check=False, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    COMMANDS.append({'argv': [str(x) for x in args], 'exit_code': p.returncode,
        'elapsed_seconds': round(time.monotonic() - start, 4), 'stdout_bytes': len(p.stdout),
        'stdout_sha256': sha(p.stdout), 'stderr_bytes': len(p.stderr), 'stderr_sha256': sha(p.stderr)})
    if p.returncode:
        raise RuntimeError(p.stderr.decode('utf-8', 'replace')[:2000])
    return p.stdout

def u32(raw, at):
    return struct.unpack_from('>I', raw, at)[0]

def boxes(raw, start=0, end=None):
    end = len(raw) if end is None else end
    out = []
    while start < end:
        assert start + 8 <= end
        size, name = struct.unpack_from('>I4s', raw, start)
        assert size >= 8 and start + size <= end, 'Own small writer must use explicit32bit boxes'
        out.append({'kind': name.decode('ascii'), 'offset': start, 'bytes': size,
                    'data': start + 8, 'end': start + size})
        start += size
    assert start == end
    return out

def child(raw, parent, kind):
    found = [b for b in boxes(raw, parent['data'], parent['end']) if b['kind'] == kind]
    assert len(found) == 1, kind
    return found[0]

def full(raw, box):
    value = u32(raw, box['data'])
    return value >> 24, value & 0xffffff

def init_metadata(raw, moov):
    mvex, trak = child(raw, moov, 'mvex'), child(raw, moov, 'trak')
    tkhd = child(raw, trak, 'tkhd'); version, flags = full(raw, tkhd)
    assert version == 0
    track_id = u32(raw, tkhd['data'] + 12)
    mdia = child(raw, trak, 'mdia'); mdhd = child(raw, mdia, 'mdhd')
    assert full(raw, mdhd)[0] == 0
    timescale, duration = u32(raw, mdhd['data'] + 12), u32(raw, mdhd['data'] + 16)
    hdlr = child(raw, mdia, 'hdlr'); assert raw[hdlr['data'] + 8:hdlr['data'] + 12] == b'vide'
    minf = child(raw, mdia, 'minf'); stbl = child(raw, minf, 'stbl')
    empty = {}
    for name in ('stts', 'stsc', 'stco'):
        box = child(raw, stbl, name); assert full(raw, box) == (0, 0)
        empty[name] = u32(raw, box['data'] + 4); assert empty[name] == 0
    stsz = child(raw, stbl, 'stsz'); empty['stsz'] = u32(raw, stsz['data'] + 8)
    assert empty['stsz'] == 0
    stsd = child(raw, stbl, 'stsd'); assert full(raw, stsd) == (0, 0)
    assert u32(raw, stsd['data'] + 4) == 1
    entry = boxes(raw, stsd['data'] + 8, stsd['end']); assert len(entry) == 1 and entry[0]['kind'] == 'avc1'
    entry = entry[0]
    avcc = [b for b in boxes(raw, entry['data'] + 78, entry['end']) if b['kind'] == 'avcC']
    assert len(avcc) == 1
    config = raw[avcc[0]['data']:avcc[0]['end']]; assert config[0] == 1 and (config[4] & 3) + 1 == 4
    trex = child(raw, mvex, 'trex'); assert full(raw, trex) == (0, 0) and trex['end'] - trex['data'] == 24
    fields = struct.unpack_from('>5I', raw, trex['data'] + 4)
    assert fields[0] == track_id and fields[1] == 1
    return {'track_id': track_id, 'timescale': timescale, 'init_media_duration': duration,
            'codec': 'avc1', 'nal_length_bytes': 4, 'avcc_sha256': sha(config),
            'empty_init_sample_tables': empty,
            'trex': dict(zip(('track_id', 'sample_description_index', 'default_duration', 'default_size', 'default_flags'), fields))}

def parse_pair(raw, moof, mdat, init):
    assert moof['end'] == mdat['offset']
    mfhd = child(raw, moof, 'mfhd'); assert full(raw, mfhd) == (0, 0)
    sequence = u32(raw, mfhd['data'] + 4)
    traf = child(raw, moof, 'traf'); tfhd = child(raw, traf, 'tfhd')
    version, flags = full(raw, tfhd); assert version == 0
    assert flags & 0x020000 and not flags & (0x000001 | 0x010000)
    assert flags & ~0x02003b == 0
    at = tfhd['data'] + 4
    track_id = u32(raw, at); at += 4
    assert track_id == init['track_id']
    defaults = {key: init['trex'][key] for key in ('sample_description_index', 'default_duration', 'default_size', 'default_flags')}
    for bit, name in ((2, 'sample_description_index'), (8, 'default_duration'), (16, 'default_size'), (32, 'default_flags')):
        if flags & bit:
            defaults[name] = u32(raw, at); at += 4
    assert at == tfhd['end'] and defaults['sample_description_index'] == 1
    tfdt = child(raw, traf, 'tfdt'); tv, tflags = full(raw, tfdt)
    assert tv in (0, 1) and tflags == 0
    decode_time = struct.unpack_from('>Q' if tv else '>I', raw, tfdt['data'] + 4)[0]
    assert tfdt['end'] - tfdt['data'] == (12 if tv else 8)
    trun = child(raw, traf, 'trun'); rv, rflags = full(raw, trun)
    assert rv in (0, 1) and rflags & 1 and rflags & ~0xf05 == 0
    count = u32(raw, trun['data'] + 4); assert count == 4
    at = trun['data'] + 8
    data_offset = struct.unpack_from('>i', raw, at)[0]; at += 4
    first_flags = None
    if rflags & 4:
        first_flags = u32(raw, at); at += 4
    cursor = moof['offset'] + data_offset
    assert cursor == mdat['data']
    time_cursor = decode_time; samples = []
    for n in range(count):
        duration, size, sample_flags, cts = defaults['default_duration'], defaults['default_size'], defaults['default_flags'], 0
        if n == 0 and first_flags is not None:
            sample_flags = first_flags
        for bit, key in ((0x100, 'duration'), (0x200, 'size'), (0x400, 'flags'), (0x800, 'cts')):
            if rflags & bit:
                value = struct.unpack_from('>i' if key == 'cts' and rv else '>I', raw, at)[0]; at += 4
                if key == 'duration': duration = value
                elif key == 'size': size = value
                elif key == 'flags': sample_flags = value
                else: cts = value
        assert duration > 0 and size > 0 and cts == 0 and cursor + size <= mdat['end']
        samples.append({'offset': cursor, 'bytes': size, 'dts': time_cursor, 'pts': time_cursor + cts,
                        'duration': duration, 'flags': sample_flags, 'sha256': sha(raw[cursor:cursor + size])})
        cursor += size; time_cursor += duration
    assert at == trun['end'] and cursor == mdat['end']
    return {'mfhd_sequence': sequence, 'track_id': track_id, 'tfhd_flags': flags,
            'tfdt_version': tv, 'base_decode_time': decode_time, 'end_decode_time': time_cursor,
            'trun_version': rv, 'trun_flags': rflags, 'data_offset_from_moof': data_offset,
            'moof_offset': moof['offset'], 'moof_bytes': moof['bytes'],
            'mdat_offset': mdat['offset'], 'mdat_bytes': mdat['bytes'], 'samples': samples}

def parse_mfra(raw, mfra, pairs):
    tfra, mfro = child(raw, mfra, 'tfra'), child(raw, mfra, 'mfro')
    version, flags = full(raw, tfra); assert version in (0, 1) and flags == 0
    at = tfra['data'] + 4; track = u32(raw, at); at += 4
    lengths = u32(raw, at); at += 4
    count = u32(raw, at); at += 4
    entries = []
    for n in range(count):
        time_value, offset = struct.unpack_from('>QQ' if version else '>II', raw, at); at += 16 if version else 8
        indexes = []
        for shift in (4, 2, 0):
            width = ((lengths >> shift) & 3) + 1
            indexes.append(int.from_bytes(raw[at:at + width], 'big')); at += width
        entries.append({'time': time_value, 'moof_offset': offset, 'traf_number': indexes[0],
                        'trun_number': indexes[1], 'sample_number': indexes[2]})
    assert at == tfra['end'] and count == 3
    assert [e['moof_offset'] for e in entries] == [p['moof_offset'] for p in pairs]
    assert [e['time'] for e in entries] == [p['base_decode_time'] for p in pairs]
    assert full(raw, mfro) == (0, 0) and u32(raw, mfro['data'] + 4) == mfra['bytes']
    return {'track_id': track, 'tfra_version': version, 'entries': entries, 'mfro_size': mfra['bytes']}

def main():
    original_path = HERE / 'original.mp4'
    assert not original_path.exists() and not (HERE / 'image.dd').exists(), 'Fresh witness paths required'
    assert file_sha(FF) == FF_SHA and file_sha(FP) == FP_SHA
    protected = {str(p): file_sha(p) for p in (FF, FP)}
    run([FF, '-v', 'error', '-nostdin', '-n', '-f', 'lavfi', '-i', 'testsrc2=size=160x96:rate=6',
         '-frames:v', '12', '-an', '-map_metadata', '-1', '-fflags', '+bitexact', '-flags:v', '+bitexact',
         '-c:v', 'libx264', '-threads', '1', '-preset', 'medium', '-crf', '24', '-g', '4', '-keyint_min', '4',
         '-sc_threshold', '0', '-bf', '0', '-movflags', '+empty_moov+default_base_moof+frag_keyframe', original_path])
    raw = original_path.read_bytes(); top = boxes(raw)
    assert [b['kind'] for b in top] == ['ftyp', 'moov', 'moof', 'mdat', 'moof', 'mdat', 'moof', 'mdat', 'mfra']
    init = init_metadata(raw, top[1])
    pairs = [parse_pair(raw, top[i], top[i + 1], init) for i in (2, 4, 6)]
    assert [p['mfhd_sequence'] for p in pairs] == [1, 2, 3]
    assert pairs[0]['base_decode_time'] == 0
    assert all(a['end_decode_time'] == b['base_decode_time'] for a, b in zip(pairs, pairs[1:]))
    index = parse_mfra(raw, top[-1], pairs)
    packets_raw = run([FP, '-v', 'error', '-select_streams', 'v:0', '-show_packets',
        '-show_entries', 'packet=pos,size,pts,dts,duration,flags,data_hash', '-show_data_hash', 'sha256', '-of', 'json', original_path])
    packets = json.loads(packets_raw)['packets']
    samples = [sample for pair in pairs for sample in pair['samples']]
    assert len(packets) == len(samples) == 12
    for packet, sample in zip(packets, samples):
        assert all(int(packet[key]) == sample[other] for key, other in
                   [('pos', 'offset'), ('size', 'bytes'), ('pts', 'pts'), ('dts', 'dts'), ('duration', 'duration')])
        assert packet['data_hash'].lower() == 'sha256:' + sample['sha256']
    (HERE / 'packets.json').write_bytes(packets_raw)
    streams_raw = run([FP, '-v', 'error', '-select_streams', 'v:0', '-show_streams', '-of', 'json', original_path])
    streams = json.loads(streams_raw)['streams']; assert len(streams) == 1 and streams[0]['codec_name'] == 'h264'
    assert streams[0]['has_b_frames'] == 0 and streams[0]['time_base'] == '1/' + str(init['timescale'])
    (HERE / 'streams.json').write_bytes(streams_raw)
    frames = run([FF, '-v', 'error', '-nostdin', '-i', original_path, '-map', '0:v:0', '-an', '-f', 'framemd5', '-'])
    canonical = b'\n'.join(line for line in frames.splitlines() if line and not line.startswith(b'#'))
    assert len(canonical.splitlines()) == 12
    (HERE / 'original.framemd5').write_bytes(frames)
    image = bytearray(bytes([0xa7]) * (2 * 1024 * 1024)); pieces = []
    placements = [(top[0]['offset'], top[0]['end'], 32768, 'ftyp'),
                  (top[1]['offset'], top[1]['end'], 1048576, 'init_moov'),
                  (top[2]['offset'], top[3]['end'], 1572864, 'fragment_1_moof_mdat'),
                  (top[4]['offset'], top[5]['end'], 262144, 'fragment_2_moof_mdat'),
                  (top[6]['offset'], top[7]['end'], 786432, 'fragment_3_moof_mdat'),
                  (top[8]['offset'], top[8]['end'], 1966080, 'mfra')]
    parts = HERE / 'parts'; parts.mkdir()
    for start, end, physical, kind in placements:
        payload = raw[start:end]
        assert image[physical:physical + len(payload)] == bytes([0xa7]) * len(payload)
        image[physical:physical + len(payload)] = payload
        (parts / (kind + '.bin')).write_bytes(payload)
        pieces.append({'logical_offset': start, 'source_offset': physical, 'bytes': len(payload),
                       'kind': kind, 'sha256': sha(payload), 'part_file': 'parts/' + kind + '.bin'})
    replay = b''.join(image[p['source_offset']:p['source_offset'] + p['bytes']] for p in pieces)
    assert replay == raw and image.find(raw) < 0
    for i, piece in enumerate(pieces):
        assert piece['logical_offset'] == sum(p['bytes'] for p in pieces[:i])
        assert all(piece['source_offset'] + piece['bytes'] <= p['source_offset'] or
                   p['source_offset'] + p['bytes'] <= piece['source_offset'] for p in pieces[:i])
    fine = []
    for box in top:
        parent = next(p for p in pieces if p['logical_offset'] <= box['offset'] and
                      box['end'] <= p['logical_offset'] + p['bytes'])
        at = parent['source_offset'] + box['offset'] - parent['logical_offset']
        fine.append({'kind': box['kind'], 'logical_offset': box['offset'], 'source_offset': at,
                     'bytes': box['bytes'], 'sha256': sha(raw[box['offset']:box['end']])})
    (HERE / 'image.dd').write_bytes(image)
    save(HERE / 'commands.json', COMMANDS)
    witness = {'schema': 1, 'status': 'NATIVE_WRITER_AND_DECODER_ORACLE_PASS_ACTUAL_RECOVERY_NOT_RUN',
        'scope': 'Owned12frame AVC fMP4, noBframes,3intact self-relative moof+mdat pairs physically permuted; not arbitrary fMP4 recovery.',
        'original': {'path': 'original.mp4', 'bytes': len(raw), 'sha256': sha(raw)},
        'source_image': {'path': 'image.dd', 'bytes': len(image), 'sha256': sha(image)},
        'generator_sha256': file_sha(Path(__file__)), 'ffmpeg_sha256': FF_SHA, 'ffprobe_sha256': FP_SHA,
        'decoded_frames': 12, 'canonical_framemd5_sha256': sha(canonical), 'packet_oracle_sha256': file_sha(HERE / 'packets.json'),
        'init': init, 'fragments': pairs, 'mfra': index, 'physical_extents': pieces, 'top_level_atom_extents': fine,
        'all_original_bytes_survive': True, 'original_not_contiguous_in_image': True,
        'logical_sequence': [p['mfhd_sequence'] for p in pairs], 'physical_fragment_order': [2, 3, 1],
        'actual_baseline': 'NOT_RUN', 'actual_recovered_count': None,
        'ownership_uncertainty': 'Plain mfhd/track ids,tfdt times,trun sizes and mfra offsets constrain placement/order but do not authenticate stream ownership. No claim of uniqueness against foreign compatible fragments or missing-tail completion.',
        'primary_reference': {'url': 'https://www.w3.org/TR/2024/NOTE-mse-byte-stream-format-isobmff-20240723/',
            'sections': [3, 4], 'paraphrase': 'Initialization carries ftyp/moov with mvex and empty tables. Media uses moof/mdat with relative addressing, decode time and complete sample coverage.'}}
    save(HERE / 'witness.json', witness)
    assert all(file_sha(Path(path)) == digest for path, digest in protected.items())
    save(HERE / 'after.json', {'protected_sha256': {path: file_sha(Path(path)) for path in protected},
                               'unchanged': True, 'actual_recovery': 'NOT_RUN'})
    print(json.dumps({'status': 'PASS', 'original_sha256': sha(raw), 'image_sha256': sha(image),
                      'frames': 12, 'fragments': 3, 'actual_recovery': 'NOT_RUN',
                      'witness_sha256': file_sha(HERE / 'witness.json')}))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', required=True)
    parser.add_argument('--ffmpeg', required=True)
    parser.add_argument('--ffprobe', required=True)
    args = parser.parse_args()
    HERE = Path(args.destination).absolute()
    FF, FP = Path(args.ffmpeg).absolute(), Path(args.ffprobe).absolute()
    HERE.mkdir(parents=True, exist_ok=False)
    main()
