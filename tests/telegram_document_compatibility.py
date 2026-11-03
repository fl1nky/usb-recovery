"""Explicit current policy for five independently reserialized old controls.

Historical oracle bytes, zero-result goldens and source factories stay intact.
No recovery code is used to decide which exact inputs qualify for the upgrade.
"""
from pathlib import Path
import base64
import functools
import gzip
import hashlib
import io
import json

BUNDLE = Path(__file__).resolve().parent / 'fixtures/telegram-document-attributes-compatibility'
MANIFEST_SHA256 = '27075f5e9ca95c54c0e07163bdf22d3756cdc7ef756e1baeff3fffa415d10f33'
OLD_MANIFEST_SHA256 = '8b2d3c7b6fe1f259607ef18987bcd51625412aad9a59c747f72980b212f712f7'
UPGRADED = frozenset('reject-media-flags-bit' + str(bit) for bit in (3, 4, 6, 7, 8))


@functools.lru_cache(maxsize=1)
def policy():
    raw = (BUNDLE / 'manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError('Changed native compatibility manifest')
    manifest = json.loads(raw)
    if (manifest['source_fixture_manifest_sha256'] != OLD_MANIFEST_SHA256 or
            set(manifest['compatibility_case_names']) != UPGRADED or
            {row['path'] for row in manifest['files']} != {'compatibility.json.gz', 'oracle-sources.tar.gz', 'LICENSE', 'README.md'}):
        raise ValueError('Changed native compatibility scope')
    for row in manifest['files']:
        raw = (BUNDLE / row['path']).read_bytes()
        if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('Changed native compatibility payload')
    with gzip.GzipFile(fileobj=io.BytesIO((BUNDLE / 'compatibility.json.gz').read_bytes())) as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) != manifest['uncompressed_json_bytes'] or hashlib.sha256(raw).hexdigest() != manifest['uncompressed_json_sha256']:
        raise ValueError('Changed or oversized native compatibility JSON')
    payload = json.loads(raw)
    if payload['old_fixture_manifest_sha256'] != OLD_MANIFEST_SHA256 or set(payload['policy']['upgrade_control_names']) != UPGRADED:
        raise ValueError('Changed explicit compatibility policy')
    cases = {row['name']: row for row in payload['cases'] if row['name'] in UPGRADED}
    native = {row['name']: row for row in payload['native_results']}
    if set(cases) != UPGRADED or len(payload['cases']) != 6 or len(native) != 6:
        raise ValueError('Incomplete whole-BLOB native proofs')
    for name, row in cases.items():
        proof = native[name]
        if (proof['scope'] != 'WHOLE_BLOB_NATIVE_EXACT' or
                proof['outputs']['blob']['sha256'] != row['blob_sha256'] or
                proof['outputs']['body']['sha256'] != row['tl_body_sha256']):
            raise ValueError('Missing exact native serialization proof')
    return cases


def current_case(case):
    """Return a separate expectation overlay; never mutate historical goldens."""
    if case['name'] not in UPGRADED:
        return case
    proof = policy()[case['name']]
    for key, expected in proof['old_metadata'].items():
        actual = case['blob'] if key == 'blob_base64' else case.get(key)
        if key == 'blob_base64':
            expected = base64.b64decode(expected, validate=True)
        if actual != expected:
            raise ValueError('Historical control differs from the exact native proof: ' + key)
    if case['expected'] != proof['expected_message'] or case['exact_sql'] != proof['exact_sql']:
        raise ValueError('Changed native field/SQL compatibility binding')
    return dict(case, expected_native_parts=1, current_profile_policy='native_boolean_compatibility')
