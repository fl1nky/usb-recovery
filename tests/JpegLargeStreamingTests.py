"""Large JPEG correctness with real bounded checkpoint/resume searches.

All searches retain the production 300-second wall clock. The expensive late
alternative can span acknowledged work slices; each must advance its durable
cursor. CPU/wall observations are diagnostics, not performance claims.
"""
from contextlib import contextmanager
from pathlib import Path
import argparse
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'helpers/recovery_engine'))
import fragmented_photos as photos
from fragmented_photos import PhotoAssembler, LimitReached, recover
from jpeg_fragments import recover_jpegs
from PIL import Image
from build_large_jpeg_fixtures import build, sha
from build_progressive_jpeg_fixtures import markers


@contextmanager
def fake_guard_clock(clock):
    """Cheap guard controls only; real searches never replace their clock."""
    original, wall = photos.time, time.monotonic
    try:
        with patch.object(photos, 'time', SimpleNamespace(monotonic=clock)):
            assert time.monotonic is wall
            yield
    finally:
        assert photos.time is original and time.monotonic is wall


def clock_controls(source):
    """Exercise the unchanged 300 boundary without waiting or doing a join."""
    assert photos.time is time
    ticks, rejected = [0.0], []
    def limit(call, expected):
        try:
            call()
        except LimitReached as error:
            assert str(error) == expected
            rejected.append(expected)
        else:
            raise AssertionError('Expected unchanged timeout guard: '+expected)
    with source.open('rb') as stream, fake_guard_clock(lambda: ticks[0]):
        assembler = PhotoAssembler(stream)
        assembler.index()
        ticks[0] = 300.0
        assert assembler.read(0, 1) == source.read_bytes()[:1]
        before = assembler.verified
        ticks[0] = 300.001
        limit(lambda: assembler.read(0, 1), 'time_budget')
        assert assembler.verified == before
        limit(assembler.index, 'index_time_budget')
        limit(lambda: list(recover_jpegs(assembler)), 'time_budget')
    # Also prove the default dependency still measures real monotonic time.
    assert photos.time is time
    with source.open('rb') as stream:
        assembler = PhotoAssembler(stream)
        assembler.started = time.monotonic()-301
        limit(lambda: assembler.read(0, 0), 'time_budget')
        limit(assembler.index, 'index_time_budget')
    return dict(Name='clock-boundary-controls', At300Allowed=True,
                Past300Rejected=rejected, ModuleClockRestored=True,
                GlobalMonotonicUnchanged=True, PerformanceClaim=False)


def search(source, parser=recover_jpegs):
    before = sha(source.read_bytes())
    started, cpu_started = time.monotonic(), time.process_time()
    assert photos.time is time
    with source.open('rb') as stream:
        assembler = PhotoAssembler(stream)
        assembler.index()
        try:
            found = list(parser(assembler))
        except LimitReached as error:
            found = []
            assembler.skipped[str(error)] += 1
    assert sha(source.read_bytes()) == before
    elapsed, cpu = round(time.monotonic()-started,3), round(time.process_time()-cpu_started,3)
    return found,dict(Seconds=elapsed, WallSeconds=elapsed, CpuSeconds=cpu,
                      BudgetClock='production_wall_monotonic', BudgetSeconds=300,
                      PerformanceClaim=False, Skipped=dict(assembler.skipped),
                      VerifiedBytes=assembler.verified,SourceSha256=before)


def checkpoint_position(state):
    """Lexicographic durable work position; counts or new filenames cannot fake progress."""
    if state['Phase'] == 'index':
        return (0, state['Index']['Position'])
    current = state.get('JpegSearch')
    assert current is not None and current['Phase'] in ('prefix', 'join'), state['Phase']
    if current['Phase'] == 'prefix':
        return (1, current['Start'], 0, current['NextCut'])
    active = current['Active']
    return (1, current['Start'], 1, current['End'], current['Prefix'],
            current['Physical'], active[4] if active is not None else -1)


def resume_search(source, output, *, slice_cpu_seconds=90, max_turns=8, first_boundary_quota=None):
    """Use actual recovery checkpoints; CPU time only requests an early safe slice.

    No real clock is substituted. A natural wall timeout remains limited. The
    optional first-boundary quota is only for cheap harness sanity checks.
    """
    assert photos.time is time and slice_cpu_seconds > 0 and max_turns <= 8
    before = sha(source.read_bytes())
    anchors, history, previous, previous_sequence = [], [], None, 0
    original_read = PhotoAssembler.read
    boundary = dict(CpuStart=0.0, Reads=0, Injected=False, Turn=0, Cause=None)

    # Keep one executing code object for the complete anchored checkpoint chain.
    def sliced_read(assembler, offset, length):
        current, caller = assembler.jpeg_stream_state, sys._getframe(1)
        if (offset == length == 0 and current is not None and
                caller.f_globals.get('__name__') == 'jpeg_fragments' and
                caller.f_code.co_name == 'boundary' and
                current['Phase'] in ('prefix', 'join')):
            result = original_read(assembler, offset, length)
            boundary['Reads'] += 1
            forced = (boundary['Turn'] == 0 and first_boundary_quota is not None and
                      boundary['Reads'] >= first_boundary_quota)
            if forced or time.process_time()-boundary['CpuStart'] >= slice_cpu_seconds:
                boundary['Injected'] = True
                boundary['Cause'] = 'owned_first_boundary' if forced else 'cpu_quantum'
                raise LimitReached('jpeg_stream_owned_cpu_slice_incomplete')
            return result
        return original_read(assembler, offset, length)

    wall_start, cpu_start = time.monotonic(), time.process_time()
    for turn in range(max_turns):
        assert sha(source.read_bytes()) == before and photos.time is time
        options = {} if not anchors else dict(resume_checkpoint=anchors[-1])
        started, cpu_started = time.monotonic(), time.process_time()
        boundary.update(CpuStart=cpu_started, Reads=0, Injected=False, Turn=turn, Cause=None)
        with patch.object(PhotoAssembler, 'read', sliced_read):
            report = recover(source, output, options, checkpoint_progress=anchors.append)
        assert PhotoAssembler.read is original_read and photos.time is time
        assert sha(source.read_bytes()) == before == report['SourceSha256']
        assert report['SourceUnchanged'] and report['ResumedFromCheckpoint'] == (turn > 0)
        assert anchors and anchors[-1]['Sequence'] > previous_sequence
        previous_sequence = anchors[-1]['Sequence']
        state = json.loads(Path(anchors[-1]['Path']).read_text(encoding='utf-8-sig'))
        position = None if report['Status'] == 'complete' else checkpoint_position(state)
        if position is not None:
            assert previous is None or position > previous, dict(Previous=previous, Current=position)
            previous = position
        history.append(dict(Turn=turn,Status=report['Status'],Candidates=report['Candidates'],
                            Position=position,Sequence=previous_sequence,Injected=boundary['Injected'],
                            SliceCause=boundary['Cause'],
                            SafeReadBoundaries=boundary['Reads'],WallSeconds=round(time.monotonic()-started,3),
                            CpuSeconds=round(time.process_time()-cpu_started,3),Skipped=report['Skipped'],
                            BudgetClock='production_wall_monotonic',BudgetSeconds=300,
                            SliceCpuQuantum=slice_cpu_seconds,PerformanceClaim=False))
        print(json.dumps(dict(Name='late-alternative-resume-turn',**history[-1])),flush=True)
        if report['Status'] == 'complete':
            break
        assert report['Status'] == 'limited' and (output/'job.incomplete').exists(), report
        assert report['Candidates'] == 0, 'No ambiguity witness is published before the proof completes'
        assert boundary['Injected'] or any(key in report['Skipped'] for key in ('time_budget','index_time_budget')), report['Skipped']
    else:
        raise AssertionError(dict(Reason='Late-alternative did not complete within bounded advancing resumes',History=history))
    assert not (output/'job.incomplete').exists()
    found = []
    with source.open('rb') as stream:
        for row in report['Files']:
            recipe = []
            for extent in row['Extents']:
                stream.seek(extent['ImageOffset'])
                raw = stream.read(extent['Length'])
                assert len(raw) == extent['Length']
                recipe.append((extent['ImageOffset'], raw))
            payload = b''.join(raw for _,raw in recipe)
            assert (output/row['Path']).read_bytes() == payload
            assert sha(payload) == row['Sha256'] and len(payload) == row['Bytes']
            found.append((recipe,row['Status'],row['Note']))
    assert sha(source.read_bytes()) == before
    elapsed, cpu = round(time.monotonic()-wall_start,3), round(time.process_time()-cpu_start,3)
    return found,dict(Seconds=elapsed,WallSeconds=elapsed,CpuSeconds=cpu,
                      BudgetClock='production_wall_monotonic',BudgetSeconds=300,
                      SliceCpuQuantum=slice_cpu_seconds,MaxTurns=max_turns,History=history,
                      FirstBoundaryQuota=first_boundary_quota,
                      PerformanceClaim=False,Skipped=report['Skipped'],
                      VerifiedBytes=report['VerifiedBytes'],SourceSha256=before)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--baseline', action='store_true', help='Optional paired historical comparison, requires the Git base')
    args = parser.parse_args()
    destination = (args.destination or ROOT/'.build'/('jpeg-large-source-'+uuid.uuid4().hex[:8])).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    results = []
    try:
        fixtures = destination/'fixtures'
        manifest = build(fixtures)
        original = (fixtures/'original.jpg').read_bytes()
        original_pixels = manifest['PixelSha256']
        results.append(clock_controls(fixtures/'exact.dd'))
        print(json.dumps(results[-1]),flush=True)
        if args.baseline:
            old_source = subprocess.check_output(['git','-C',str(ROOT),'show',
                                                   '5684800:helpers/recovery_engine/jpeg_fragments.py'])
            old_path = destination/'baseline-jpeg.py'
            old_path.write_bytes(old_source)
            spec = importlib.util.spec_from_file_location('baseline_jpeg_owned',old_path)
            baseline = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(baseline)
            found, fact = search(fixtures/'exact.dd',baseline.recover_jpegs)
            assert not found
            results.append(dict(Name='baseline-large-exact',Candidates=0,**fact))
            print(json.dumps(results[-1]),flush=True)
        for name in ('exact','late-alternative','overwritten','missing-eoi'):
            if name == 'late-alternative':
                found, fact = resume_search(fixtures/(name+'.dd'), destination/'late-alternative-resumed')
            else:
                found, fact = search(fixtures/(name+'.dd'))
            if name == 'exact':
                assert len(found)==1, fact
                recipe,status,note = found[0]
                payload = b''.join(raw for _,raw in recipe)
                assert payload==original and status=='jpeg_gap_structural_candidate'
                assert [(at,len(raw)) for at,raw in recipe] == [
                    (e['ImageOffset'],e['Length']) for e in manifest['Cases'][0]['Extents']]
                with Image.open(io.BytesIO(payload)) as decoded:
                    decoded.load()
                    assert sha(decoded.tobytes())==original_pixels
                assert 'not authenticated' in note
            elif name == 'late-alternative':
                assert len(found)==2, fact
                assert {sha(b''.join(raw for _,raw in row[0])) for row in found} == {
                    manifest['OriginalSha256'],manifest['AlternateSha256']}
                assert all(row[1]=='jpeg_gap_ambiguous_candidate' for row in found)
                alternate = (fixtures/'alternate.jpg').read_bytes()
                # The independent writer scatters the alternative tail at
                # physical 65536, with the same original prefix/cut.
                original_map = manifest['Cases'][0]['Extents']
                cut = original_map[1]['LogicalOffset']
                alternate_map = [(original_map[0]['ImageOffset'], cut),
                                 (65536, len(alternate)-cut)]
                references = {
                    manifest['OriginalSha256']: (original, [(e['ImageOffset'],e['Length']) for e in original_map]),
                    manifest['AlternateSha256']: (alternate, alternate_map),
                }
                for recipe, _, _ in found:
                    payload = b''.join(raw for _,raw in recipe)
                    reference, expected_map = references[sha(payload)]
                    assert payload == reference
                    assert [(at,len(raw)) for at,raw in recipe] == expected_map
                    with Image.open(io.BytesIO(reference)) as native, Image.open(io.BytesIO(payload)) as decoded:
                        native.load(); decoded.load()
                        assert sha(decoded.tobytes()) == sha(native.tobytes())
            else:
                assert not found, fact
            results.append(dict(Name='current-large-'+name,Candidates=len(found),**fact))
            print(json.dumps(results[-1]),flush=True)
        # Inject work boundaries after real parser reads, independently of CPU speed.
        anchors, history, output = [], [], destination/'resumed'
        original_read = PhotoAssembler.read
        cancelled = False
        prior_prefix = None
        join_head = None
        for turn, target_phase in enumerate(('prefix', 'prefix', 'join', None)):
            quota = 128 if target_phase == 'prefix' else 2
            boundary = dict(Mode='slice', Quota=quota, Reads=0, Injected=False, Start=None, Caller=None)
            def sliced_read(assembler, offset, length):
                current = assembler.jpeg_stream_state
                caller = sys._getframe(1)
                in_parser = (caller.f_globals.get('__name__') == 'jpeg_fragments' and
                             caller.f_code.co_name in {'baseline_stream_paths', 'boundary'})
                if (target_phase is not None and current is not None and
                        current['Phase'] == target_phase and in_parser and
                        (target_phase == 'join' or offset == length == 0)):
                    boundary['Reads'] += 1
                    if boundary['Reads'] == boundary['Quota']:
                        boundary.update(Injected=True, Start=current['Start'], Caller=caller.f_code.co_name)
                        if boundary['Mode'] == 'cancel':
                            raise InterruptedError('owned large JPEG cancellation')
                        raise LimitReached('jpeg_stream_owned_slice_incomplete')
                return original_read(assembler, offset, length)
            options = {} if not anchors else dict(resume_checkpoint=anchors[-1])
            wall_started, cpu_started = time.monotonic(), time.process_time()
            with patch.object(PhotoAssembler, 'read', sliced_read):
                report = recover(fixtures/'exact.dd', output, options, checkpoint_progress=anchors.append)
            state = json.loads(Path(anchors[-1]['Path']).read_text(encoding='utf-8'))
            current = state.get('JpegSearch')
            position = None if current is None else [current['Phase'],current['NextCut'],current['End'],current['Prefix'],current['Physical'],current['Active']]
            history.append(dict(Turn=turn,Status=report['Status'],Candidates=report['Candidates'],
                                Position=position,Injected=boundary['Injected'],ReadBoundaries=boundary['Reads'],ReadCaller=boundary['Caller'],
                                WallSeconds=round(time.monotonic()-wall_started,3),
                                CpuSeconds=round(time.process_time()-cpu_started,3),
                                BudgetClock='production_wall_monotonic',BudgetSeconds=300,PerformanceClaim=False))
            print(json.dumps(history[-1]),flush=True)
            if target_phase is None:
                assert report['Status'] == 'complete' and report['Candidates'] == 1
                assert report['ResumedFromCheckpoint'] and cancelled and turn > 1
                row = report['Files'][0]
                payload = (output/row['Path']).read_bytes()
                assert payload == original and row['Extents'] == manifest['Cases'][0]['Extents']
                with Image.open(io.BytesIO(payload)) as decoded:
                    decoded.load()
                    assert sha(decoded.tobytes()) == original_pixels
                break
            assert boundary['Injected'] and report['Status'] == 'limited'
            assert report['Candidates'] == 0 and not list(output.glob('*.jpg'))
            assert current is not None and current['Phase'] == target_phase
            assert current['Start'] == boundary['Start']
            if target_phase == 'prefix':
                assert prior_prefix is None or current['NextCut'] > prior_prefix
                prior_prefix = current['NextCut']
            else:
                join_head = current['Start']
                # Keep the same patched code object across retries, as required
                # by the checkpoint's real code-fingerprint binding.
                boundary.update(Mode='cancel', Quota=1, Reads=0, Injected=False, Start=None, Caller=None)
                try:
                    with patch.object(PhotoAssembler, 'read', sliced_read):
                        recover(fixtures/'exact.dd', output, dict(resume_checkpoint=anchors[-1]),
                                checkpoint_progress=anchors.append)
                except InterruptedError:
                    cancelled = True
                else:
                    raise AssertionError('Cancellation inside the head join did not execute')
                retained = json.loads(Path(anchors[-1]['Path']).read_text(encoding='utf-8'))['JpegSearch']
                assert cancelled and boundary['Injected'] and boundary['Reads'] == 1
                assert retained['Phase'] == 'join' and retained['Start'] == boundary['Start'] == join_head
                assert retained['NextCut'] >= current['NextCut']
                assert not list(output.glob('*.jpg'))
                assert sha((fixtures/'exact.dd').read_bytes()) == manifest['Cases'][0]['SourceSha256']
                print(json.dumps(dict(Cancelled=True,Phase='join',Start=join_head,ReadBoundaries=boundary['Reads'],ReadCaller=boundary['Caller'])),flush=True)
        assert cancelled and len({json.dumps(h['Position']) for h in history[:-1]}) == len(history)-1
        results.append(dict(Name='large-sliced-cancel-resume',History=history,JoinHead=join_head,Cancelled=cancelled,
                            BudgetClock='production_wall_monotonic',BudgetSeconds=300,PerformanceClaim=False))
        # Actual large native restart/progressive layouts, with independent
        # marker-defined cuts. A resource limit is retained as a limit.
        for name in ('restart','progressive'):
            raw = (fixtures/(name+'.jpg')).read_bytes()
            boundaries = [end for _,end,code in markers(raw) if 0xd0<=code<=0xd7]
            assert len(boundaries)>10
            cuts = [0,boundaries[len(boundaries)//3],boundaries[2*len(boundaries)//3],len(raw)]
            places = [8*1024*1024,1024*1024,12*1024*1024]
            data = bytearray(b'\xcc'*(16*1024*1024))
            for left,right,at in zip(cuts,cuts[1:],places):
                data[at:at+right-left]=raw[left:right]
            source=fixtures/(name+'.dd');source.write_bytes(data)
            found,fact=search(source)
            if found:
                assert len(found)==1 and b''.join(raw for _,raw in found[0][0])==raw
            else:
                assert fact['Skipped'], 'Unsupported/limited must remain explicit'
            results.append(dict(Name='large-'+name,Candidates=len(found),**fact))
            print(json.dumps(results[-1]),flush=True)
        print('PASS: large JPEG correctness with bounded advancing resumes; production 300-second wall guard unchanged; no performance/portable/device claim',flush=True)
    finally:
        (destination/'results.json').write_text(json.dumps(results,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':
    main()
