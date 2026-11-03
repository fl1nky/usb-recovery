"""Independent large JPEG byte/pixel/map, ambiguity and sliced-resume proof."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import time
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'helpers/recovery_engine'))
from fragmented_photos import PhotoAssembler, LimitReached, recover
from jpeg_fragments import recover_jpegs
from PIL import Image
from build_large_jpeg_fixtures import build, sha
from build_progressive_jpeg_fixtures import markers


def search(source, parser=recover_jpegs):
    before = sha(source.read_bytes())
    started = time.monotonic()
    with source.open('rb') as stream:
        assembler = PhotoAssembler(stream)
        assembler.index()
        try:
            found = list(parser(assembler))
        except LimitReached as error:
            found = []
            assembler.skipped[str(error)] += 1
    assert sha(source.read_bytes()) == before
    return found,dict(Seconds=round(time.monotonic()-started,3),Skipped=dict(assembler.skipped),
                      VerifiedBytes=assembler.verified,SourceSha256=before)


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
            else:
                assert not found, fact
            results.append(dict(Name='current-large-'+name,Candidates=len(found),**fact))
            print(json.dumps(results[-1]),flush=True)
        # No restarted search can repeatedly consume the first giant prefix.
        anchors, history, output = [],[],destination/'resumed'
        cancelled = False
        for turn in range(40):
            started = time.monotonic()
            def sliced(done,total):
                if time.monotonic()-started > 8:
                    raise LimitReached('jpeg_stream_owned_slice_incomplete')
            options = {} if not anchors else dict(resume_checkpoint=anchors[-1])
            report = recover(fixtures/'exact.dd',output,options,progress=sliced,checkpoint_progress=anchors.append)
            state = json.loads(Path(anchors[-1]['Path']).read_text(encoding='utf-8'))
            current = state.get('JpegSearch')
            position = None if current is None else [current['Phase'],current['NextCut'],current['End'],current['Prefix'],current['Physical'],current['Active']]
            history.append(dict(Turn=turn,Status=report['Status'],Candidates=report['Candidates'],Position=position))
            print(json.dumps(history[-1]),flush=True)
            if report['Status']=='complete':
                assert report['Candidates']==1 and (output/report['Files'][0]['Path']).read_bytes()==original
                assert report['ResumedFromCheckpoint'] and turn>1
                break
            assert report['Candidates']==0 and not list(output.glob('*.jpg'))
            if not cancelled and current is not None and current['Phase']=='join':
                # Cancellation inside the same head also retains parser work.
                started = time.monotonic()
                def interrupt(done,total):
                    if time.monotonic()-started > 1:
                        raise InterruptedError('owned large JPEG cancellation')
                try:
                    recover(fixtures/'exact.dd',output,dict(resume_checkpoint=anchors[-1]),progress=interrupt,checkpoint_progress=anchors.append)
                except InterruptedError:
                    cancelled = True
                else:
                    raise AssertionError('Cancellation did not execute')
        else:
            raise AssertionError('Sliced search failed to finish')
        assert cancelled and len({json.dumps(h['Position']) for h in history[:-1]})==len(history)-1
        results.append(dict(Name='large-sliced-cancel-resume',History=history))
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
        print('PASS: large JPEG source checks; limits remain explicit, no portable/device claim',flush=True)
    finally:
        (destination/'results.json').write_text(json.dumps(results,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':
    main()
