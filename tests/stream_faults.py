"""Owned stream wrappers for deterministic partial-write and failure tests."""
from pathlib import Path
from unittest.mock import patch


class LimitedWriter:
    def __init__(self, stream, limit=65535, invalid=None):
        self.stream, self.limit, self.invalid = stream, limit, invalid

    def __enter__(self): return self
    def __exit__(self, *args): return self.stream.__exit__(*args)
    def __getattr__(self, name): return getattr(self.stream, name)
    def write(self, block):
        if self.invalid is not None:
            return self.invalid[0]
        return self.stream.write(block[:self.limit])


def limited_open(predicate, invalid=None):
    original = Path.open

    def open_stream(path, mode='r', *args, **kwargs):
        stream = original(path, mode, *args, **kwargs)
        return LimitedWriter(stream, invalid=invalid) if predicate(path, mode) else stream
    return patch.object(Path, 'open', open_stream)
