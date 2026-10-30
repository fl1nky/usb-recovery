"""Read-only audit of owned, saved benchmark archives and scorer regressions."""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import sys

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / 'tests/benchmarks'))
import score_telegram_recovery as scorer


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def context(run, name):
    folder = run / name
    source = Path(load(folder / 'analyze-request.json')['options']['roots'][0])
    if not source.resolve().is_relative_to((REPO / '.build').resolve()):
        raise ValueError('Only saved owned .build fixtures are allowed')
    kind = name.split('-', 1)[0]
    manifest = load(source.parent.parent / 'manifest.json')
    case = next(item for item in manifest['cases'] if item['name'] == name[len(kind) + 1:])
    rows = [json.loads(line) for line in (folder / 'archive/messages.jsonl').read_text(encoding='utf-8').splitlines()]
    expected = case.get('expected_text_sha256') or scorer.text_sha(case['latest_text'])
    matches = [row for row in rows if scorer.text_sha(row.get('text')) == expected]
    return kind, case, source, rows, matches, folder


def mutation_checks(run):
    kind, case, source, rows, matches, folder = context(run, 'wal-torn-after-commit')
    wrong = copy.deepcopy(matches[0])
    wrong.update(message_id=999, chat_id=999)
    wrong_result = scorer.score(kind, case, source, [wrong], {}, True)
    replies = [json.loads(line) for line in (folder / 'literal_all-stdout.jsonl').read_text(encoding='utf-8').splitlines()]
    reply = next(value for value in replies if value.get('event') == 'result')
    view = next(row for row in reply['records'] if row.get('recovery_status') == 'committed_wal_prefix_snapshot')
    stripped = {key: value for key, value in view.items()
                if not key.startswith(('wal_', 'sqlite_', 'native_tl_')) and key != 'proof'}
    missing_result = scorer.score(kind, case, source, rows, {'literal_all': {**reply, 'records': [stripped]}}, True)
    kind, case, source, rows, matches, _ = context(run, 'overflow-page-512')
    fake = copy.deepcopy(matches[0])
    raw = source.read_bytes()
    parts = copy.deepcopy(fake['sqlite_payload_ranges'][:2])
    for index, part in enumerate(parts):
        part['logical_offset'], part['bytes'] = index * 8, 8
    chunks = [raw[part['physical_byte_offset']:part['physical_byte_offset'] + 8] for part in parts]
    fake.update(sqlite_payload_ranges=parts, sqlite_payload_length=16,
                sqlite_payload_sha256=scorer.sha(b''.join(chunks)), sqlite_record_length=8,
                sqlite_record_sha256=scorer.sha(chunks[0]), sqlite_overflow_pages=[parts[1]['sqlite_page']])
    short_result = scorer.score(kind, case, source, [fake], {}, True)
    kind, case, source, rows, matches, _ = context(run, 'overflow-page-4096')
    raw, original = source.read_bytes(), matches[0]
    parts = original['sqlite_payload_ranges']
    duplicate = next((left, right) for left in range(1, len(parts)) for right in range(left + 1, len(parts))
                     if parts[left]['bytes'] == parts[right]['bytes'] and
                     raw[parts[left]['physical_byte_offset']:parts[left]['physical_byte_offset'] + parts[left]['bytes']] ==
                     raw[parts[right]['physical_byte_offset']:parts[right]['physical_byte_offset'] + parts[right]['bytes']])
    fake = copy.deepcopy(original)
    parts, (left, right) = fake['sqlite_payload_ranges'], duplicate
    for key in ('sqlite_page', 'physical_byte_offset'):
        parts[left][key], parts[right][key] = parts[right][key], parts[left][key]
    fake['sqlite_overflow_pages'] = [part['sqlite_page'] for part in parts[1:]]
    actual_links = []
    for index, part in enumerate(parts):
        at = part['physical_byte_offset'] + part['bytes'] if index == 0 else (part['sqlite_page'] - 1) * 4096
        actual_links.append(int.from_bytes(raw[at:at + 4], 'big'))
    assert actual_links != [part['sqlite_page'] for part in parts[1:]] + [0]
    chain_result = scorer.score(kind, case, source, [fake], {}, True)
    found = dict(wrong_chat_and_message_ids_verified_prefix_count=wrong_result['verified_prefix_count'],
                 search_view_without_wal_provenance_full_proof_count=missing_result['searches']['literal_all']['full_proof_target_views'],
                 sixteen_byte_map_for_long_gold_text_verified_overflow_count=short_result['verified_overflow_count'],
                 swapped_identical_blocks_with_broken_pointer_chain_verified_overflow_count=chain_result['verified_overflow_count'])
    assert all(value == 0 for value in found.values()), found
    return found


def raw_run_checks(run):
    document = load(run / 'run.json')
    before, after = load(run / 'binding-before.json'), load(run / 'binding-after.json')
    assert before == after
    assert sha(run / 'binding-before.json') == document['binding_before_sha256']
    assert sha(run / 'binding-after.json') == document['binding_after_sha256']
    assert len(document['results']) == 19 and document['source_runtime_code_unchanged'] is True
    summaries = []
    for saved in document['results']:
        kind, case, source, rows, exact, folder = context(run, saved['name'])
        assert sha(source) == case['source_sha256'] == saved['source_sha256']
        if kind == 'wal':
            assert sha(Path(str(source) + '-wal')) == case['wal_sha256'] == saved['wal_sha256']
        assert sha(folder / 'analyze-stdout.jsonl') == saved['execution']['stdout_sha256']
        assert sha(folder / 'analyze-stderr.bin') == saved['execution']['stderr_sha256']
        assert saved['status'] == 'completed' and saved['execution']['exit_code'] == 0
        for name, expected in saved['archive_files'].items():
            artifact = folder / 'archive' / name
            assert artifact.stat().st_size == expected['bytes'] and sha(artifact) == expected['sha256']
        mid, chat = (case['message_id'], 77) if kind == 'overflow' else (21, -88 if case['topic'] else 77)
        attributed = [row for row in exact if row.get('app') == 'Telegram' and row.get('application_confirmed') is True
                      and row.get('evidence_kind') in ('backup', 'previous', 'export')
                      and type(row.get('message_id')) is int and row['message_id'] == mid
                      and type(row.get('chat_id')) is int and row['chat_id'] == chat]
        expected_text = case.get('latest_text')
        if kind == 'overflow':
            page = int(case['name'].split('-')[1])
            repeat = 9000 if page == 65536 else 1200 if page == 4096 else 600
            expected_text = 'recipe 3 яблоки ' * repeat
            assert scorer.text_sha(expected_text) == case['expected_text_sha256']
        summaries.append(dict(name=saved['name'], exact_full_text=bool(exact), attributed_full_text=bool(attributed),
                              full_target_contained_in_any_record=any(expected_text in row.get('text', '') for row in rows)))
    return dict(application_sha256=document['application_sha256'], helper_sha256=document['helper_sha256'],
                run_sha256=sha(run / 'run.json'), all_19_cases_completed_once=True,
                source_and_archive_hashes_verified=True,
                exact_full_text_cases=sum(row['exact_full_text'] for row in summaries),
                attributed_full_text_cases=sum(row['attributed_full_text'] for row in summaries),
                contains_full_target_cases=sum(row['full_target_contained_in_any_record'] for row in summaries), cases=summaries)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    base = REPO / '.build/benchmarks-v7-telegram'
    result = dict(schema=1, scope='Pure read-only scorer regression and independent saved-archive verification; no program reruns',
                  scorer_revision=scorer.REVISION, scorer_sha256=sha(REPO / 'tests/benchmarks/score_telegram_recovery.py'),
                  mutation_counts=mutation_checks(base / 'v7-final-01'),
                  actual_v6=raw_run_checks(base / 'v6-baseline-01'), actual_v7=raw_run_checks(base / 'v7-final-01'))
    with args.output.open('x', encoding='utf-8') as target:
        json.dump(result, target, indent=2)
    print(json.dumps({key: {name: value for name, value in data.items() if name != 'cases'} if isinstance(data, dict) else data
                      for key, data in result.items()}))


if __name__ == '__main__':
    main()
