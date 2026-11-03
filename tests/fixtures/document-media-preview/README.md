# Preview fixture

`avc-aac.mp4` is the existing controlled `phone-fast.mp4` output of `tests/build_fragmented_media_audio_fixtures.py`, retained byte-for-byte so preview tests can run offline without FFmpeg or Python. It contains synthetic test imagery and synthesized sine audio, with no user data. This fixture is dedicated under CC0-1.0. The SHA256 and decoder oracle counts are fixed in `manifest.json`.

PDF fixtures are generated directly by the C# test from a three-page solid-color and text oracle; they are not copied from third-party documents.
