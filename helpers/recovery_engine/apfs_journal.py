# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authenticated-caller-only, durable APFS file ledger and copy checkpoints."""
import json
import os
from pathlib import Path

from recovery_io import RecoveryIOError, atomic, digest, plain, read_json, read_only, writable
from resumable_copy import stage, publish


class JournalLimit(Exception):
    pass


def _key(record):
    return record['volume_id'], record['snapshot_xid'], record['original_path'], record['inode']


class FileJournal:
    def __init__(self, destination, binding, resume, max_metadata):
        self.directory = Path(destination)
        self.path = self.directory / 'apfs-candidates.journal.jsonl'
        self.state = self.directory / 'apfs-resume.json'
        self.checkpoints = self.directory / 'apfs-resume'
        self.records, self.by_key, self.seen = [], {}, set()
        self.metadata_bytes, self.max_metadata = 0, max_metadata
        if self.state.exists():
            if not resume:
                raise RecoveryIOError('RESUME_REQUIRED')
            if read_json(self.state) != {'schema': 1, 'binding': binding}:
                raise RecoveryIOError('RESUME_SOURCE_CHANGED')
        else:
            if resume:
                raise RecoveryIOError('RESUME_CHECKPOINT_INVALID')
            atomic(self.state, {'schema': 1, 'binding': binding})
        self.binding = binding
        for directory in (self.directory / 'apfs-files', self.checkpoints):
            plain(str(directory))
            directory.mkdir(exist_ok=True)
        if self.path.exists():
            writable(self.path)
            if self.path.stat().st_size > max_metadata + 256 * 1024:
                raise RecoveryIOError('RESUME_CHECKPOINT_INVALID')
            raw = self.path.read_bytes()
            # A killed append may leave an incomplete final line; committed rows
            # are never rewritten or silently repaired.
            committed = raw.rfind(b'\n') + 1
            try:
                for line in raw[:committed].splitlines(keepends=True):
                    record = json.loads(line)
                    relative = record['path']
                    suffix = Path(relative).suffix
                    expected = 'apfs-files/' + str(len(self.records) + 1).zfill(8) + suffix
                    if (relative != expected or not suffix or len(suffix) > 16
                            or not all(c.isascii() and (c.isalnum() or c == '.') for c in suffix)
                            or type(record['bytes']) is not int or record['bytes'] < 0
                            or len(record['sha256']) != 64 or any(c not in '0123456789abcdef' for c in record['sha256'])
                            or _key(record) in self.by_key):
                        raise ValueError()
                    self.records.append(record)
                    self.by_key[_key(record)] = record
                    self.metadata_bytes += len(line)
            except (KeyError, ValueError, TypeError):
                raise RecoveryIOError('RESUME_CHECKPOINT_INVALID') from None
            if self.metadata_bytes > max_metadata:
                raise RecoveryIOError('RESUME_CHECKPOINT_INVALID')
            if committed < len(raw):
                with self.path.open('r+b') as journal:
                    journal.truncate(committed)
                    journal.flush()
                    os.fsync(journal.fileno())

    def contains(self, template):
        return _key(template) in self.by_key

    def export(self, template, extension, open_reader, emit=None):
        identity = _key(template)
        prior = self.by_key.get(identity)
        record = dict(template)
        record['path'] = prior['path'] if prior else 'apfs-files/' + str(len(self.records) + 1).zfill(8) + extension
        output = self.directory / record['path']
        checkpoint = self.checkpoints / (Path(record['path']).stem + '.json')
        if prior:
            if {k: v for k, v in prior.items() if k != 'sha256'} != record:
                raise RecoveryIOError('RESUME_SOURCE_CHANGED')
            if output.exists() and not checkpoint.exists():
                plain(str(output), True)
                with read_only(output) as data:
                    if os.fstat(data.fileno()).st_size != record['bytes'] or digest(data) != prior['sha256']:
                        raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
                self.seen.add(identity)
                return True
        elif output.exists():
            raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
        estimated = json.dumps(dict(record, sha256='0' * 64), ensure_ascii=False) + '\n'
        if not prior and len(estimated.encode('utf-8')) > self.max_metadata - self.metadata_bytes:
            raise JournalLimit()
        appended = bool(prior)
        try:
            with open_reader() as reader:
                staged = stage(reader, record['bytes'], output, {'source': self.binding, 'record': record},
                               True, emit, 'export-file', checkpoint)
                reader.seek(record['bytes'])
                if reader.read(1):
                    raise RecoveryIOError('SOURCE_SIZE_CHANGED')
            record['sha256'] = staged['sha256']
            if prior and record != prior:
                raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
            if not prior:
                encoded = (json.dumps(record, ensure_ascii=False) + '\n').encode('utf-8')
                writable(self.path)
                with self.path.open('ab') as journal:
                    journal.write(encoded)
                    journal.flush()
                    os.fsync(journal.fileno())
                appended = True
                self.metadata_bytes += len(encoded)
                self.records.append(record)
                self.by_key[identity] = record
            # A durable row precedes publication. On restart an authenticated
            # reader can verify and finish the retained complete partial.
            publish(staged, output)
            writable(checkpoint)
            checkpoint.unlink(missing_ok=True)
            self.seen.add(identity)
            return bool(prior)
        except RecoveryIOError:
            raise
        except Exception:
            if not appended:
                for path in (output.with_name(output.name + '.partial'), checkpoint):
                    writable(path)
                    path.unlink(missing_ok=True)
            raise

    def finish(self):
        if self.seen != set(self.by_key):
            raise RecoveryIOError('RESUME_RECORD_NOT_FOUND')
