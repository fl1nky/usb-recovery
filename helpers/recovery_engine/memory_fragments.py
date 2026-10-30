"""Strings from supplied dumps only; no process access or chat attribution.

Offsets refer to bytes in the supplied file, never virtual memory addresses.
Overlapping windows keep cross-block strings, with bounded memory and results.
Only original read-only working copies are scanned. No credentials are sought.
"""
import re

CHUNK = 1024 * 1024
OVERLAP = 65536
MAX_FRAGMENTS = 20_000
UTF8 = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee-\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2}){8,8192}")
# Latin/Cyrillic UTF-16 runs. Arbitrary binary interpreted as wide Unicode
# produces convincing nonsense, so unsupported scripts are not guessed here.
LE = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e\xa0-\xff]\x00|[\x00-\xff][\x01-\x05]){8,8192}")
BE = re.compile(rb"(?:\x00[\x09\x0a\x0d\x20-\x7e\xa0-\xff]|[\x01-\x05][\x00-\xff]){8,8192}")


def plausible(text):
    letters = sum(c.isalpha() for c in text)
    return len(text.strip()) >= 8 and letters >= 5 and letters / len(text) >= 0.40 and all(c.isprintable() or c in "\r\n\t" for c in text)


def scan(path, matcher, progress=None, limit=MAX_FRAGMENTS):
    count, carry, position = 0, b"", 0
    last_end = {name: -1 for name in ("utf-8", "utf-16-le", "utf-16-be")}
    with path.open("rb") as source:
        while True:
            block = source.read(CHUNK)
            final = not block
            data = carry + block
            base = position - len(carry)
            # Delay the overlapping tail until the following block, preserving
            # complete strings at a block boundary without duplicate findings.
            safe_end = len(data) if final else max(0, len(data) - OVERLAP)
            for encoding, pattern in (("utf-8", UTF8), ("utf-16-le", LE), ("utf-16-be", BE)):
                for match in pattern.finditer(data):
                    start, end = base + match.start(), base + match.end()
                    if match.start() >= safe_end or start < last_end[encoding]:
                        continue
                    if not final and match.end() > safe_end:
                        continue
                    last_end[encoding] = end
                    text = match.group().decode(encoding)
                    if plausible(text) and matcher.matches(text):
                        yield {"text": text, "byte_offset": start, "byte_length": end - start, "encoding": encoding}
                        count += 1
                        if count >= limit:
                            return
            if final:
                return
            # Retain a full extra maximum string before the delayed tail, so a
            # start just before safe_end is reconsidered with its full context.
            carry = data[-2 * OVERLAP:]
            position += len(block)
            if progress:
                progress(position)


def scan_tl(path, matcher, progress=None, limit=MAX_FRAGMENTS, cancel=None):
    """Strict public TL bodies in supplied dumps, retaining unknown context.

    This never obtains a process dump. Byte offsets refer to the given file,
    and decoded peer/date/ID fields stay *candidates*, not attributed chats.
    """
    from sqlite_deleted import tl_fragments
    count, carry, position, last_end = 0, b"", 0, -1
    with path.open("rb") as source:
        while True:
            if cancel is not None and cancel():
                from sqlite_deleted import DeletedError
                raise DeletedError("CANCELLED")
            block = source.read(CHUNK)
            final = not block
            data = carry + block
            base = position - len(carry)
            safe_end = len(data) if final else max(0, len(data) - OVERLAP)
            for value in tl_fragments(data, cancel=cancel):
                start = base + value["byte_offset"]
                end = start + value["byte_length"]
                if start < last_end or value["byte_offset"] >= safe_end:
                    continue
                if not final and end > base + safe_end:
                    continue
                last_end = end
                if matcher is not None and not matcher.matches(value["text"]):
                    continue
                value.update(byte_offset=start, physical_byte_offset=start,
                             physical_source="supplied_dump", sqlite_region=None)
                yield value
                count += 1
                if count >= limit:
                    return
            if final:
                return
            carry = data[-2 * OVERLAP:]
            position += len(block)
            if progress:
                progress(position)
