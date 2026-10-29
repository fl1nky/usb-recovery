"""Local, read-only v3 import worker. Runtime protocol is UTF-8 NDJSON on stdin/stdout.

Passwords never enter argument lists or persisted job state. All parsers operate on
temporary copies. No input HTML, external URL or script is ever executed.
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib
import html
import io
import json
import logging
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from html.parser import HTMLParser

MAX_IMAGE = 128 * 1024 * 1024
MAX_PIXELS = 60_000_000
MAX_TEXT = 128 * 1024 * 1024
MAX_DB = 1024 * 1024 * 1024
MAX_ZIP = 16 * 1024 * 1024 * 1024
MAX_ZIP_FILES = 100_000
SCHEMA = 1
EVIDENCE = {"export", "backup", "previous", "fragment"}
LABELS = {"export": "из экспорта", "backup": "из резервной копии",
          "previous": "предыдущая версия", "fragment": "текстовый фрагмент"}


class RecoveryError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def within(path, base):
    try:
        Path(path).resolve().relative_to(Path(base).resolve())
        return True
    except (ValueError, OSError):
        return False


def reparse(path):
    st = Path(path).lstat()
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def safe_relative(value):
    """Reject Windows paths as well when executing tests on another OS."""
    if not isinstance(value, str) or not value or value in (".", "./") or "\x00" in value:
        raise RecoveryError("UNSAFE_PATH")
    v = value.replace("\\", "/")
    p = PurePosixPath(v)
    if p.is_absolute() or any(x in ("..", "") for x in p.parts) or ":" in v:
        raise RecoveryError("UNSAFE_PATH")
    if any(x.rstrip(" .") != x or x.split(".")[0].upper() in
           {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)],
            *[f"LPT{i}" for i in range(1, 10)]} for x in p.parts):
        raise RecoveryError("UNSAFE_PATH")
    return p


def files_under(root):
    root = Path(root)
    if reparse(root):
        raise RecoveryError("REPARSE_SOURCE")
    if root.is_file():
        yield root
        return
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not reparse(Path(directory) / d))
        for name in sorted(names):
            p = Path(directory) / name
            if not reparse(p) and p.is_file():
                yield p


def emit(event, **fields):
    # Never forward upstream diagnostics: some crypto packages interpolate keys.
    sys.stdout.write(json.dumps({"protocol": 1, "type": event, "event": event, **fields}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def utc_timestamp(value, apple=False):
    if value is None:
        return None
    try:
        number = float(value)
        if apple:
            number += 978307200
        if number > 99_999_999_999:
            number /= 1000
        return dt.datetime.fromtimestamp(number, dt.timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return str(value)


def jpeg_end(data, start=0):
    """Locate JPEG EOI while respecting APP/EXIF and entropy marker framing."""
    if data[start:start + 2] != b"\xff\xd8":
        return None
    pos, entropy = start + 2, False
    while pos < len(data):
        if entropy:
            marker_start = data.find(b"\xff", pos)
            if marker_start < 0:
                return None
            pos = marker_start
        if data[pos] != 255:
            return None
        while pos < len(data) and data[pos] == 255:
            pos += 1
        if pos >= len(data):
            return None
        marker = data[pos]
        pos += 1
        if entropy and (marker == 0 or 0xD0 <= marker <= 0xD7):
            continue
        entropy = False
        if marker == 0xD9:
            return pos
        if marker == 0xD8 or marker == 0:
            return None
        if marker == 1 or 0xD0 <= marker <= 0xD7:
            continue
        if pos + 2 > len(data):
            return None
        length = int.from_bytes(data[pos:pos + 2], "big")
        if length < 2 or pos + length > len(data):
            return None
        pos += length
        entropy = marker == 0xDA
    return None


class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.blocked = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.blocked += 1
        elif tag == "br" and not self.blocked:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.blocked = max(0, self.blocked - 1)

    def handle_data(self, data):
        if not self.blocked:
            self.parts.append(data)


def plain_markup(value):
    parser = TextOnly()
    parser.feed(str(value or ""))
    return "".join(parser.parts)


class TelegramHTML(HTMLParser):
    """Extract Telegram export message containers, never render source markup."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.messages = []
        self.stack = []
        self.current = None
        self.depth = 0
        self.blocked = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style"):
            self.blocked += 1
        if tag in ("br", "img", "meta", "link", "input", "hr", "source", "wbr"):
            if tag == "br" and self.current and not self.blocked:
                self.current["text"] += "\n"
            return
        classes = attrs.get("class", "").split()
        role = next((c for c in ("text", "from_name", "date") if c in classes), None)
        self.stack.append((tag, role))
        if tag == "div" and "message" in classes and "default" in classes:
            self.current = {"message_id": attrs.get("id", "").removeprefix("message") or None,
                            "text": "", "sender_name": "", "timestamp": None,
                            "attachment_refs": []}
            self.depth = len(self.stack)
        if self.current and role == "date" and attrs.get("title"):
            self.current["timestamp"] = attrs["title"]
        if self.current and tag == "a" and attrs.get("href"):
            self.current["attachment_refs"].append(attrs["href"])

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.blocked = max(0, self.blocked - 1)
        if self.current and len(self.stack) == self.depth and tag == "div":
            self.messages.append(self.current)
            self.current = None
        if self.stack:
            self.stack.pop()

    def handle_data(self, data):
        if not self.current or self.blocked:
            return
        roles = [role for _, role in self.stack]
        if "text" in roles:
            self.current["text"] += data
        elif "from_name" in roles:
            self.current["sender_name"] += data


def safe_unzip(source, target):
    count = size = 0
    with zipfile.ZipFile(source) as z:
        for info in z.infolist():
            count += 1
            size += info.file_size
            if count > MAX_ZIP_FILES or size > MAX_ZIP:
                raise RecoveryError("ZIP_LIMIT")
            if info.flag_bits & 1:
                raise RecoveryError("ZIP_ENCRYPTED_UNSUPPORTED")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise RecoveryError("UNSAFE_ZIP")
            rel = safe_relative(info.filename.rstrip("/"))
            p = Path(target).joinpath(*rel.parts)
            if not within(p, target):
                raise RecoveryError("UNSAFE_ZIP")
            if info.is_dir():
                p.mkdir(parents=True, exist_ok=True)
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as inp, p.open("xb") as out:
                shutil.copyfileobj(inp, out, 1024 * 1024)
    return count


class Importer:
    def __init__(self, source, destination, secrets=None, deep=True, tools_dir=None, scratch=None):
        self.source = Path(source).resolve()
        self.output = Path(destination).resolve()
        self.secrets = dict(secrets or {})
        self.deep = deep
        self.tools_dir = Path(tools_dir) if tools_dir else None
        self.scratch = Path(scratch).resolve() if scratch else None
        self.messages = []
        self.photos = {}
        self.sources = []
        self.identities = {}
        self.handled = set()
        self.attachment_map = {}
        self.attachments = {}
        self.snapshot = None
        self.source_label = None
        self.extracted_roots = []
        self.work = None
        self.source_count = 0
        self.origins = {}
        self.current_origin = {}
        self.original_source = self.source
        self.telegram_only = False

    def remark(self, code, source=None, **details):
        self.sources.append({"code": code, "source": str(source or self.source_label or self.source), **details})

    def message(self, app, text, evidence="export", **fields):
        m = {"app": app, "snapshot_id": self.snapshot, "chat_id": None,
             "sender_id": None, "sender_name": None, "timestamp": None,
             "text": str(text or ""), "message_id": None, "evidence_kind": evidence,
             "source_file": self.source_label, "source_record": None, "attachments": [], **fields}
        if self.current_origin:
            m["source_id"] = self.current_origin.get("Id")
            m["original_relative_path"] = self.current_origin.get("RelativePath")
            m["source_sha256"] = self.current_origin.get("Sha256")
        if evidence not in EVIDENCE:
            raise RecoveryError("INVALID_EVIDENCE")
        # IDs and chat identity are required for deduplication. Exports with no
        # confirmed IDs deliberately remain separate even when text is identical.
        # Native local DBs can belong to different Telegram accounts, whose
        # numeric dialog/message IDs overlap. Only an explicit verified scope
        # joins their snapshots; legacy exports keep their existing identity.
        key = (app, m.get("identity_scope"), m.get("record_kind") or "message", m["chat_id"], m["message_id"])
        if m["chat_id"] is not None and m["message_id"] is not None and evidence != "fragment":
            candidates = self.identities.setdefault(key, [])
            for previous in candidates:
                # Equal captions/IDs are insufficient when a photo was replaced
                # or removed in a later committed snapshot. Preserve those
                # versions even if neither source contains full image bytes.
                if all(previous.get(k) == m.get(k) for k in ("text", "sender_id", "timestamp", "attachments",
                        "media_kind", "media_id", "media_status", "thumbnail_count")):
                    previous.setdefault("additional_sources", []).append(
                        {name: m.get(name) for name in ("snapshot_id", "source_file", "source_record", "source_sha256",
                            "wal_commit_frame", "wal_proof", "wal_sha256", "wal_snapshot_sha256") if m.get(name) is not None})
                    return
            if candidates and evidence == "previous":
                m["evidence_kind"] = "previous"
            candidates.append(m)
        self.messages.append(m)

    def attachment(self, reference, base):
        if not reference or not isinstance(reference, str):
            return None
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", reference) or reference.startswith(("/", "\\")):
            return None
        try:
            rel = safe_relative(reference)
            p = Path(base).joinpath(*rel.parts)
            if not within(p, base) or not p.is_file() or reparse(p):
                self.remark("ATTACHMENT_MISSING", reference)
                return None
            if p.stat().st_size > 4 * MAX_DB:
                self.remark("ATTACHMENT_TOO_LARGE", reference)
                return None
            h = digest(p)
            attachment_origin = self.origins.get(str(p.resolve()), {})
            origin = {"source_file": self.source_label, "source_record": reference,
                      "snapshot_id": self.snapshot,
                      "original_path": attachment_origin.get("OriginalPath") or f"{self.source_label}!/{reference}",
                      "source_id": attachment_origin.get("Id") or self.current_origin.get("Id"),
                      "original_relative_path": attachment_origin.get("RelativePath") or reference}
            if h in self.attachment_map:
                if origin not in self.attachments[h]["sources"]:
                    self.attachments[h]["sources"].append(origin)
                return self.attachment_map[h]
            ext = p.suffix.lower()
            if not re.fullmatch(r"\.[a-z0-9]{1,12}", ext) or ext in {".html", ".htm", ".xhtml", ".mhtml", ".mht", ".svg", ".js", ".hta"}:
                ext = ".bin"
            existing = self.photos.get(h)
            target = self.output / existing["path"] if existing else self.output / "media" / f"{h}{ext}"
            target.parent.mkdir(exist_ok=True)
            if not target.exists():
                shutil.copyfile(p, target)
            result = target.relative_to(self.output).as_posix()
            self.attachment_map[h] = result
            self.attachments[h] = {"sha256": h, "path": result, "size": p.stat().st_size, "sources": [origin]}
            return result
        except (OSError, RecoveryError):
            self.remark("ATTACHMENT_UNAVAILABLE", reference)
            return None

    def telegram_json(self, path):
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            return False
        if self.telegram_only:
            from telegram_auto import _export_json
            if not _export_json(data):
                return False
        chats = data.get("chats", {}).get("list", []) if isinstance(data.get("chats"), dict) else []
        if "messages" in data and isinstance(data["messages"], list):
            chats = [data]
        if not chats:
            return False
        for chat_index, chat in enumerate(chats):
            if not isinstance(chat, dict) or not isinstance(chat.get("messages"), list):
                continue
            for n, m in enumerate(chat["messages"]):
                if not isinstance(m, dict):
                    continue
                value = m.get("text", "")
                if isinstance(value, list):
                    value = "".join(x if isinstance(x, str) else str(x.get("text", ""))
                                    for x in value if isinstance(x, (dict, str)))
                refs = [m.get("photo"), m.get("file")]
                attachments = [x for r in refs if (x := self.attachment(r, path.parent))]
                self.message("Telegram", value, chat_id=chat.get("id"),
                             sender_id=m.get("from_id"), sender_name=m.get("from"),
                             timestamp=m.get("date"), message_id=m.get("id"),
                             source_record=f"messages[{n}]" if chats == [data] else f"chats.list[{chat_index}].messages[{n}]", attachments=attachments,
                             chat_name=chat.get("name"), message_type=m.get("type"))
        return True

    def telegram_html(self, path):
        parser = TelegramHTML()
        parser.feed(path.read_text(encoding="utf-8-sig", errors="replace"))
        if not parser.messages:
            return False
        self.remark("HTML_CHAT_ID_UNKNOWN", path)
        for n, m in enumerate(parser.messages):
            attachments = [x for r in m.pop("attachment_refs") if (x := self.attachment(r, path.parent))]
            m["sender_name"] = m["sender_name"].strip() or None
            self.message("Telegram", m.pop("text").strip(), source_record=f"container[{n}]",
                         attachments=attachments, **m)
        return True

    def whatsapp_text(self, path):
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        # Android and iOS exports, dots/slashes/hyphens, 12/24-hour timestamps,
        # bidi marks and NBSP. Dates are intentionally not guessed for 01/02.
        pattern = re.compile(r"^[\u200e\u200f\ufeff]*(?:\[)?(\d{1,4}[./-]\d{1,2}[./-]\d{1,4}),?\s+"
                             r"(\d{1,2}:\d{2}(?::\d{2})?(?:[\s\u202f\xa0]*[AaPp][Mm])?)(?:\])?\s*(?:[-–]\s*)?(.*)$")
        matches = []
        for n, line in enumerate(text.splitlines(), 1):
            m = pattern.match(line)
            if m:
                date, time, body = m.groups()
                sender, sep, content = body.partition(": ")
                matches.append({"date": date, "time": time, "sender": sender if sep else None,
                                "text": content if sep else body, "line": n})
            elif matches:
                matches[-1]["text"] += "\n" + line
        if not matches:
            return False
        date_parts = [re.split(r"[./-]", m["date"]) for m in matches]
        dmy = any(len(p[0]) != 4 and int(p[0]) > 12 for p in date_parts)
        mdy = any(len(p[0]) != 4 and int(p[1]) > 12 for p in date_parts)
        for m, parts in zip(matches, date_parts):
            date = None
            ambiguous = False
            try:
                if len(parts[0]) == 4:
                    y, mo, d = map(int, parts)
                elif dmy != mdy:
                    d, mo = (int(parts[0]), int(parts[1])) if dmy else (int(parts[1]), int(parts[0]))
                    y = int(parts[2])
                    y += 2000 if y < 100 else 0
                else:
                    ambiguous = True
                    raise ValueError
                time = m["time"].replace("\u202f", " ").replace("\xa0", " ")
                for fmt in ("%H:%M", "%H:%M:%S", "%I:%M %p", "%I:%M:%S %p"):
                    try:
                        parsed = dt.datetime.strptime(time.upper(), fmt).time()
                        date = dt.datetime.combine(dt.date(y, mo, d), parsed).isoformat()
                        break
                    except ValueError:
                        pass
            except ValueError:
                pass
            refs = re.findall(r"<attached:\s*([^>]+)>", m["text"], flags=re.IGNORECASE)
            explicit = re.match(r"^(.+?)\s+\((?:file attached|файл добавлен|файл прикрепл[её]н|archivo adjunto)\)", m["text"], flags=re.IGNORECASE)
            if explicit:
                refs.append(explicit.group(1))
            attachments = [item for ref in refs if (item := self.attachment(ref.strip(), path.parent))]
            self.message("WhatsApp", m["text"], sender_name=m["sender"], timestamp=date,
                         timestamp_raw=f"{m['date']} {m['time']}", timestamp_ambiguous=ambiguous,
                         timezone_unknown=True, chat_name=path.stem, source_record=f"line:{m['line']}", attachments=attachments)
        if not dmy and not mdy:
            self.remark("DATE_ORDER_UNKNOWN", path)
        return True

    def photo(self, content, source, offset=0, embedded=False, *, record=None, blob_offset=None):
        if not content or len(content) > MAX_IMAGE:
            return
        from PIL import Image, UnidentifiedImageError
        h = hashlib.sha256(content).hexdigest()
        origin = {"source_file": str(source), "source_record": record or f"offset:{offset}",
                  "snapshot_id": self.snapshot}
        if record is None:
            origin["offset"] = offset
        elif blob_offset is not None:
            # SQLite serializes BLOB payloads across logical pages. This is
            # an offset inside one decoded TL BLOB, never a file/image offset.
            origin.update(blob_offset=blob_offset, offset_kind="sqlite_tl_blob_relative")
        if self.current_origin:
            origin.update(source_id=self.current_origin.get("Id"),
                          relative_path=self.current_origin.get("RelativePath"),
                          source_sha256=self.current_origin.get("Sha256"))
        if h in self.photos:
            if origin not in self.photos[h]["sources"]:
                self.photos[h]["sources"].append(origin)
            return
        try:
            with Image.open(io.BytesIO(content)) as im:
                width, height = im.size
                if width <= 0 or height <= 0 or width * height > MAX_PIXELS:
                    self.remark("IMAGE_PIXEL_LIMIT", source)
                    return
                fmt = im.format or "unknown"
                im.verify()
            with Image.open(io.BytesIO(content)) as im:
                im.load()
                preview = im.copy()
                preview.thumbnail((640, 640))
                if preview.mode not in ("RGB", "L"):
                    preview = preview.convert("RGB")
                ext = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp", "HEIF": ".heic",
                       "HEIC": ".heic", "GIF": ".gif", "BMP": ".bmp", "TIFF": ".tif"}.get(fmt, ".bin")
                target = self.output / self.attachment_map[h] if h in self.attachment_map else self.output / "media" / f"{h}{ext}"
                if not target.exists():
                    target.write_bytes(content)
                thumb = self.output / "previews" / f"{h}.jpg"
                preview.save(thumb, "JPEG", quality=88)
                self.photos[h] = {"sha256": h, "width": width, "height": height, "format": fmt,
                                  "size": len(content), "status": "decoded",
                                  "kind": "embedded" if embedded else ("thumbnail" if max(width, height) <= 320 else "photo"),
                                  "classification_basis": "sqlite_tl_cached_thumbnail" if record else ("embedded_offset" if embedded else ("small_dimensions_only" if max(width, height) <= 320 else "dimensions")),
                                  "path": target.relative_to(self.output).as_posix(),
                                  "thumbnail": thumb.relative_to(self.output).as_posix(), "sources": [origin]}
        except (UnidentifiedImageError, OSError, ValueError, SyntaxError, Image.DecompressionBombError):
            # A damaged signature candidate is retained separately; it is
            # never counted as a decoded photo or assigned a made-up size.
            formats = ((b"\xff\xd8\xff", "JPEG", ".jpg"),
                       (b"\x89PNG\r\n\x1a\n", "PNG", ".png"),
                       (b"GIF87a", "GIF", ".gif"), (b"GIF89a", "GIF", ".gif"))
            found = next(((fmt, ext) for signature, fmt, ext in formats if content.startswith(signature)), None)
            if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
                found = ("WEBP", ".webp")
            if found:
                fmt, ext = found
                target = self.output / self.attachment_map[h] if h in self.attachment_map else self.output / "media" / f"{h}{ext}"
                if not target.exists():
                    target.write_bytes(content)
                self.photos[h] = {"sha256": h, "width": 0, "height": 0, "format": fmt,
                                  "size": len(content), "status": "damaged_candidate", "kind": "damaged",
                                  "path": target.relative_to(self.output).as_posix(), "thumbnail": None,
                                  "sources": [origin]}
                self.remark("DAMAGED_IMAGE_CANDIDATE", source)
            return

    def scan_images(self, path):
        if path.stat().st_size == 0:
            return
        if path.stat().st_size > MAX_IMAGE:
            if self.deep:
                self.scan_large_container(path)
            return
        data = path.read_bytes()
        self.photo(data, self.source_label or path)
        full_decoded = self.photos.get(hashlib.sha256(data).hexdigest(), {}).get("status") == "decoded"
        if not self.deep:
            return
        # Strict structural end markers; bounded container carving avoids
        # treating arbitrary trailing bytes as part of an image.
        for signature, trailer in ((b"\xff\xd8\xff", b"\xff\xd9"), (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82")):
            start = 0
            candidates = 0
            while candidates < 1000:
                pos = data.find(signature, start)
                if pos < 0:
                    break
                end = jpeg_end(data, pos) if signature == b"\xff\xd8\xff" else data.find(trailer, pos + len(signature))
                if end is not None and end >= 0 and not (pos == 0 and full_decoded):
                    boundary = end if signature == b"\xff\xd8\xff" else end + len(trailer)
                    self.photo(data[pos:boundary], self.source_label or path, pos, pos != 0)
                start = pos + len(signature)
                candidates += 1
        start = 0
        for _ in range(1000):
            pos = data.find(b"RIFF", start)
            if pos < 0:
                break
            if data[pos + 8:pos + 12] == b"WEBP" and pos + 8 <= len(data):
                size = int.from_bytes(data[pos + 4:pos + 8], "little") + 8
                if 12 <= size <= MAX_IMAGE and pos + size <= len(data):
                    self.photo(data[pos:pos + size], self.source_label or path, pos, pos != 0)
            start = pos + 4

    def scan_large_container(self, path):
        """Bounded signature windows allow caches larger than an image limit."""
        signatures = ((b"\xff\xd8\xff", b"\xff\xd9"),
                      (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"), (b"RIFF", None))
        count, position, overlap = 0, 0, b""
        with path.open("rb") as scan, path.open("rb") as candidate:
            while block := scan.read(8 * 1024 * 1024):
                window = overlap + block
                window_start = position - len(overlap)
                for signature, trailer in signatures:
                    start = 0
                    while (found := window.find(signature, start)) >= 0:
                        offset = window_start + found
                        start = found + len(signature)
                        # The preceding window processed signatures beginning
                        # before this boundary; retain only new occurrences.
                        if offset < max(0, position - 11):
                            continue
                        candidate.seek(offset)
                        data = candidate.read(MAX_IMAGE)
                        if trailer:
                            end = jpeg_end(data) if signature == b"\xff\xd8\xff" else data.find(trailer, len(signature))
                            if end is not None and end >= 0:
                                boundary = end if signature == b"\xff\xd8\xff" else end + len(trailer)
                                self.photo(data[:boundary], self.source_label or path, offset, offset != 0)
                        elif data[8:12] == b"WEBP":
                            size = int.from_bytes(data[4:8], "little") + 8
                            if 12 <= size <= len(data):
                                self.photo(data[:size], self.source_label or path, offset, offset != 0)
                        count += 1
                        if count >= 1000:
                            self.remark("CONTAINER_CANDIDATE_LIMIT", self.source_label)
                            return
                position += len(block)
                overlap = window[-11:]

    def decrypt_whatsapp(self, path):
        secret = self.secrets.get("whatsapp_key")
        if not secret:
            raise RecoveryError("WHATSAPP_KEY_REQUIRED")
        if path.stat().st_size > MAX_DB:
            raise RecoveryError("DATABASE_LIMIT")
        from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
        from wa_crypt_tools.lib.key.key14 import Key14
        from wa_crypt_tools.lib.key.key15 import Key15
        from wa_crypt_tools.lib.errors import WaCryptError
        try:
            try:
                raw = bytes.fromhex(secret.replace(" ", "").replace("-", ""))
            except ValueError:
                raw = base64.b64decode(secret, validate=True)
            if raw.startswith(b"\xac\xed\x00\x05") and len(raw) <= 512:
                # Key files are Java-serialized byte arrays, parsed in memory.
                # This route does not use filename guessing, OCR or key repair.
                import javaobj.v2 as javaobj
                from wa_crypt_tools.lib.utils import javaintlist2bytes
                raw = javaintlist2bytes(javaobj.load(io.BytesIO(raw)).data)
            if len(raw) == 32:
                key = Key15(keyarray=raw)
            elif len(raw) == 131:
                key = Key14(keyarray=raw)
            else:
                raise RecoveryError("WHATSAPP_KEY_FORMAT")
            with path.open("rb") as f:
                db = DatabaseFactory.from_file(f)
                # Upstream decrypt verifies GCM/checksum before returning.
                compressed = db.decrypt(key, f.read())
            inflater = zlib.decompressobj()
            decoded = inflater.decompress(compressed, MAX_DB + 1)
            if len(decoded) > MAX_DB or inflater.unconsumed_tail or not inflater.eof:
                raise RecoveryError("DECOMPRESSION_LIMIT")
            if not decoded.startswith(b"SQLite format 3\x00"):
                raise RecoveryError("WHATSAPP_DATABASE_INVALID")
            target = self.work / f"decrypted-{digest(path)[:16]}.db"
            target.write_bytes(decoded)
            return target
        except RecoveryError:
            raise
        except (WaCryptError, ValueError, TypeError, zlib.error, AttributeError):
            raise RecoveryError("WHATSAPP_AUTHENTICATION_FAILED") from None

    def iphone_backup(self, root):
        manifest = root / "Manifest.plist"
        if not manifest.exists() or not (root / "Manifest.db").exists():
            return False
        if manifest.stat().st_size > MAX_TEXT or (root / "Manifest.db").stat().st_size > MAX_DB:
            raise RecoveryError("IOS_MANIFEST_INVALID")
        meta = plistlib.loads(manifest.read_bytes())
        info = root / "Info.plist"
        if meta.get("IsEncrypted") and info.is_file() and info.stat().st_size < MAX_TEXT:
            version = str(plistlib.loads(info.read_bytes()).get("Product Version", ""))
            if version and version.split(".")[0].isdigit() and int(version.split(".")[0]) < 13:
                raise RecoveryError("IOS_VERSION_UNSUPPORTED")
        target = self.work / f"iphone-{digest(manifest)[:16]}"
        target.mkdir()
        if meta.get("IsEncrypted"):
            secret = self.secrets.get("ios_password")
            if not secret:
                raise RecoveryError("IOS_PASSWORD_REQUIRED")
            from iphone_backup_decrypt import EncryptedBackup, IncorrectPassphraseError
            from iphone_backup_decrypt.utils import FilePlist, aes_decrypt_chunked
            class SafeEncryptedBackup(EncryptedBackup):
                def _decrypt_manifest_db_file(self):
                    if self._temporary_folder and Path(self._temp_decrypted_manifest_db_path).exists():
                        return
                    self._read_and_unlock_keybag()
                    self._temporary_folder = str(target.parent / (target.name + "-manifest-private"))
                    Path(self._temporary_folder).mkdir(exist_ok=True)
                    self._temp_decrypted_manifest_db_path = str(Path(self._temporary_folder) / "Manifest.db")
                    metadata_key = self._manifest_plist.get("ManifestKey", b"")
                    if len(metadata_key) != 44:
                        raise RecoveryError("IOS_MANIFEST_INVALID")
                    protection_class = struct.unpack("<l", metadata_key[:4])[0]
                    key = self.keybag.unwrap_key_for_class(protection_class, metadata_key[4:])
                    aes_decrypt_chunked(in_filename=self._manifest_db_path, out_filepath=self._temp_decrypted_manifest_db_path, key=key)
                    self._open_temp_database()
                    self.decrypted = True
            backup = None
            try:
                backup = SafeEncryptedBackup(backup_directory=str(root), passphrase=secret)
                backup.test_decryption()
                used = set()
                with backup.manifest_db_cursor() as cursor:
                    cursor.execute("PRAGMA quick_check")
                    if cursor.fetchone()[0] != "ok":
                        raise RecoveryError("IOS_MANIFEST_INVALID")
                    cursor.execute("SELECT fileID,domain,relativePath,flags,file FROM Files ORDER BY domain,relativePath")
                    for fileid, domain, relative, flags, blob in cursor:
                        if flags != 1:
                            continue
                        if not re.fullmatch(r"[a-fA-F0-9]{40}", str(fileid)):
                            self.remark("IOS_FILEID_INVALID", relative)
                            continue
                        try:
                            rel = safe_relative(f"{domain}/{relative}")
                        except RecoveryError:
                            self.remark("IOS_UNSAFE_PATH", relative)
                            continue
                        dest = target.joinpath(*rel.parts)
                        token = str(dest).casefold()
                        if token in used or not within(dest, target):
                            self.remark("IOS_PATH_COLLISION", relative)
                            continue
                        used.add(token)
                        source = root / fileid[:2] / fileid
                        if not source.exists():
                            source = root / fileid
                        if not source.is_file() or reparse(source) or not within(source, root):
                            self.remark("IOS_FILE_MISSING", relative)
                            continue
                        file_meta = FilePlist(blob)
                        if file_meta.filesize < 0 or file_meta.filesize > 4 * MAX_DB:
                            self.remark("IOS_FILE_TOO_LARGE", relative)
                            continue
                        if file_meta.target is not None or not stat.S_ISREG(int(file_meta.mode, 8)):
                            self.remark("IOS_SPECIAL_FILE_SKIPPED", relative)
                            continue
                        if file_meta.encryption_key is None:
                            if file_meta.filesize == 0:
                                dest.parent.mkdir(parents=True, exist_ok=True)
                                dest.write_bytes(b"")
                            continue
                        key = backup.keybag.unwrap_key_for_class(file_meta.protection_class, file_meta.encryption_key)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        # Do not use the upstream extraction path: it does not
                        # validate the manifest digest or reject size mismatch.
                        aes_decrypt_chunked(in_filename=str(source), out_filepath=str(dest), key=key)
                        if not self.ios_file_integrity(dest, blob, relative):
                            dest.unlink(missing_ok=True)
                            continue
                        self.origins[str(dest.resolve())] = {**self.origins.get(str(source.resolve()), {}),
                                                           "RelativePath": f"{domain}/{relative}"}
            except IncorrectPassphraseError:
                raise RecoveryError("IOS_PASSWORD_INCORRECT") from None
            except (ValueError, RuntimeError, OSError, KeyError, TypeError, sqlite3.DatabaseError):
                raise RecoveryError("IOS_BACKUP_INVALID") from None
            finally:
                if backup:
                    backup._cleanup()
                    backup._temporary_folder = None
                    backup._temp_manifest_db_conn = None
        else:
            con = sqlite3.connect((root / "Manifest.db").as_uri() + "?mode=ro&immutable=1", uri=True)
            try:
                if con.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise RecoveryError("IOS_MANIFEST_INVALID")
                count = 0
                used = set()
                for fileid, domain, relative, flags, blob in con.execute("SELECT fileID,domain,relativePath,flags,file FROM Files"):
                    if flags != 1:
                        continue
                    if not re.fullmatch(r"[a-fA-F0-9]{40}", str(fileid)):
                        self.remark("IOS_FILEID_INVALID", relative)
                        continue
                    try:
                        rel = safe_relative(f"{domain}/{relative}")
                    except RecoveryError:
                        self.remark("IOS_UNSAFE_PATH", relative)
                        continue
                    source = root / fileid[:2] / fileid
                    if not source.exists():
                        source = root / fileid
                    if not source.is_file() or reparse(source) or not within(source, root):
                        self.remark("IOS_FILE_MISSING", relative)
                        continue
                    dest = target.joinpath(*rel.parts)
                    token = str(dest).casefold()
                    if token in used or not within(dest, target):
                        self.remark("IOS_PATH_COLLISION", relative)
                        continue
                    used.add(token)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, dest)
                    if not self.ios_file_integrity(dest, blob, relative):
                        dest.unlink(missing_ok=True)
                        continue
                    self.origins[str(dest.resolve())] = {**self.origins.get(str(source.resolve()), {}),
                                                       "RelativePath": f"{domain}/{relative}"}
                    count += 1
                self.remark("IOS_UNENCRYPTED_EXTRACTED", root, files=count)
            finally:
                con.close()
        self.extracted_roots.append((target, str(root)))
        self.remark("IOS_CACHE_NOT_IN_BACKUP", root)
        return True

    def ios_file_integrity(self, path, blob, label):
        """iOS CBC has no MAC: verify a manifest digest when it is present.

        Keybag/class key unwrap uses RFC3394 integrity. A missing file digest
        is explicitly recorded, so the archive does not imply authentication
        that the backup format cannot supply.
        """
        if not blob:
            self.remark("IOS_FILE_METADATA_UNAVAILABLE", label)
            return True
        try:
            metadata = plistlib.loads(blob)
            objects = metadata.get("$objects", [])
            def resolve(value):
                if isinstance(value, plistlib.UID):
                    value = objects[value.data]
                if isinstance(value, dict) and "NS.data" in value:
                    value = value["NS.data"]
                return value
            root = resolve(metadata.get("$top", {}).get("root", metadata))
            expected_size = root.get("Size")
            if expected_size is not None and int(expected_size) != path.stat().st_size:
                self.remark("IOS_FILE_SIZE_MISMATCH", label)
                return False
            mode = root.get("Mode")
            if mode is not None and not stat.S_ISREG(int(mode)):
                self.remark("IOS_SPECIAL_FILE_SKIPPED", label)
                return False
            expected = resolve(root.get("Digest"))
            if expected is None:
                self.remark("IOS_FILE_INTEGRITY_UNAVAILABLE", label)
                return True
            if not isinstance(expected, bytes) or len(expected) not in (20, 32):
                raise ValueError
            hasher = hashlib.sha1() if len(expected) == 20 else hashlib.sha256()
            with path.open("rb") as inp:
                for block in iter(lambda: inp.read(1024 * 1024), b""):
                    hasher.update(block)
            if hasher.digest() != expected:
                self.remark("IOS_FILE_DIGEST_MISMATCH", label)
                return False
            return True
        except (ValueError, TypeError, KeyError, IndexError, plistlib.InvalidFileException):
            self.remark("IOS_FILE_METADATA_INVALID", label)
            return False

    def sqlite_whatsapp(self, path, evidence="backup", do_deep=True, media_base=None):
        if path.stat().st_size > MAX_DB:
            raise RecoveryError("DATABASE_LIMIT")
        temp = self.work / ("sqlite-" + hashlib.sha256(str(path).encode()).hexdigest()[:16])
        temp.mkdir(exist_ok=True)
        copied = temp / path.name
        shutil.copyfile(path, copied)
        for suffix in ("-wal", "-shm"):
            peer = Path(str(path) + suffix)
            if peer.exists() and not reparse(peer):
                shutil.copyfile(peer, Path(str(copied) + suffix))
        con = sqlite3.connect(copied.as_uri() + "?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        imported = False
        try:
            if con.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                self.remark("SQLITE_STRUCTURE_INVALID", self.source_label)
                return False
            tables = {x[0] for x in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not tables.intersection({"messages", "message", "ZWAMESSAGE"}):
                if do_deep and self.deep:
                    self.sqlite_fragments(copied, "Unknown")
                return False
            from Whatsapp_Chat_Exporter import android_handler, ios_handler
            # The pinned exporter retries OperationalError forever. A failing
            # SQLite cursor cannot make progress by retrying the same fetch.
            android_handler._fetch_row_safely = lambda cursor: cursor.fetchone()
            from Whatsapp_Chat_Exporter.data_model import ChatCollection, Timing
            from Whatsapp_Chat_Exporter.utility import check_jid_map, get_transcription_selection
            collection = ChatCollection()
            ios = "ZWAMESSAGE" in tables
            handler = ios_handler if ios else android_handler
            if not ios:
                collection.set_system("jid_map_exists", check_jid_map(con))
                collection.set_system("transcription_selection", get_transcription_selection(con))
            try:
                handler.messages(con, collection, str(media_base or path.parent), Timing(0), None, (None, None), False, True)
                for chatid, chat in collection.items():
                    for rowid, m in chat.items():
                        self.message("WhatsApp", plain_markup(m.data) if m.safe else str(m.data or ""), evidence,
                                     chat_id=chatid, chat_name=chat.name, sender_name=m.sender,
                                     timestamp=utc_timestamp(m.timestamp), message_id=m.key_id or None,
                                     source_record=f"{'ZWAMESSAGE' if ios else 'message' if 'message' in tables else 'messages'}:rowid={rowid}", from_me=m.from_me)
                imported = True
            except (sqlite3.DatabaseError, KeyError, TypeError, AttributeError):
                self.remark("WHATSAPP_SCHEMA_ADAPTER", self.source_label)
                imported = self.sqlite_schema_adapter(con, tables, evidence)
            # Associate media from concrete database paths without upstream file
            # manipulation. No HTML or upstream CLI is used.
            self.sqlite_attachments(con, tables, media_base or path.parent)
        finally:
            con.close()
        if do_deep and self.deep:
            self.sqlite_fragments(copied, "WhatsApp" if imported else "Unknown")
            self.sqlite_wal_history(path)
        return imported

    def sqlite_schema_adapter(self, con, tables, evidence):
        def cols(table):
            return {x[1] for x in con.execute(f'PRAGMA table_info("{table}")')}
        found = False
        if "messages" in tables:
            columns = cols("messages")
            if {"key_remote_jid", "data"}.issubset(columns):
                for n, row in enumerate(con.execute('SELECT rowid,* FROM "messages"')):
                    d = dict(row)
                    self.message("WhatsApp", d.get("data"), evidence, chat_id=d.get("key_remote_jid"),
                                 sender_id=d.get("remote_resource"), timestamp=utc_timestamp(d.get("timestamp")),
                                 message_id=d.get("key_id") or None, source_record=f"messages:rowid={row[0]}",
                                 from_me=d.get("key_from_me"))
                found = True
        elif {"message", "chat", "jid"}.issubset(tables):
            if {"chat_row_id", "text_data"}.issubset(cols("message")) and "jid_row_id" in cols("chat"):
                jids = {row["_id"]: row["raw_string"] for row in con.execute("SELECT _id,raw_string FROM jid")}
                chats = {row["_id"]: jids.get(row["jid_row_id"]) for row in con.execute("SELECT _id,jid_row_id FROM chat")}
                for row in con.execute('SELECT rowid,* FROM "message"'):
                    d = dict(row)
                    self.message("WhatsApp", d.get("text_data"), evidence, chat_id=chats.get(d.get("chat_row_id")),
                                 sender_id=jids.get(d.get("sender_jid_row_id")), timestamp=utc_timestamp(d.get("timestamp")),
                                 message_id=d.get("key_id") or None, source_record=f"message:rowid={row[0]}",
                                 from_me=d.get("from_me"))
                found = True
        elif "ZWAMESSAGE" in tables:
            columns = cols("ZWAMESSAGE")
            if "ZTEXT" in columns:
                sessions = {}
                if "ZWACHATSESSION" in tables and {"Z_PK", "ZCONTACTJID"}.issubset(cols("ZWACHATSESSION")):
                    sessions = {row[0]: row[1] for row in con.execute("SELECT Z_PK,ZCONTACTJID FROM ZWACHATSESSION")}
                for row in con.execute("SELECT rowid,* FROM ZWAMESSAGE"):
                    d = dict(row)
                    self.message("WhatsApp", d.get("ZTEXT"), evidence,
                                 chat_id=sessions.get(d.get("ZCHATSESSION")), sender_id=d.get("ZFROMJID"),
                                 timestamp=utc_timestamp(d.get("ZMESSAGEDATE"), apple=True),
                                 message_id=d.get("ZSTANZAID") or None, source_record=f"ZWAMESSAGE:rowid={row[0]}",
                                 from_me=d.get("ZISFROMME"))
                found = True
        if not found:
            self.remark("WHATSAPP_SCHEMA_UNKNOWN", self.source_label)
        return found

    def sqlite_attachments(self, con, tables, base):
        relations = {}
        for table, path_col, relation_col, message_table in (
                ("message_media", "file_path", "message_row_id", "message"),
                ("ZWAMEDIAITEM", "ZMEDIALOCALPATH", "ZMESSAGE", "ZWAMESSAGE"),
                ("messages", "media_name", "_id", "messages")):
            if table not in tables:
                continue
            columns = {x[1] for x in con.execute(f'PRAGMA table_info("{table}")')}
            if not {path_col, relation_col}.issubset(columns):
                continue
            for row in con.execute(f'SELECT "{relation_col}","{path_col}" FROM "{table}" WHERE "{path_col}" IS NOT NULL'):
                item = self.attachment(row[1], base)
                if item and row[0] is not None:
                    relations.setdefault(f"{message_table}:rowid={row[0]}", []).append(item)
        # Some iOS versions link ZWAMESSAGE.ZMEDIAITEM to the media row instead
        # of providing the reciprocal ZWAMEDIAITEM.ZMESSAGE field.
        if {"ZWAMESSAGE", "ZWAMEDIAITEM"}.issubset(tables):
            message_cols = {x[1] for x in con.execute('PRAGMA table_info("ZWAMESSAGE")')}
            media_cols = {x[1] for x in con.execute('PRAGMA table_info("ZWAMEDIAITEM")')}
            if {"Z_PK", "ZMEDIAITEM"}.issubset(message_cols) and {"Z_PK", "ZMEDIALOCALPATH"}.issubset(media_cols):
                for row in con.execute('SELECT m.Z_PK,a.ZMEDIALOCALPATH FROM ZWAMESSAGE m JOIN ZWAMEDIAITEM a ON a.Z_PK=m.ZMEDIAITEM WHERE a.ZMEDIALOCALPATH IS NOT NULL'):
                    item = self.attachment(row[1], base)
                    if item:
                        relations.setdefault(f"ZWAMESSAGE:rowid={row[0]}", []).append(item)
        for message in self.messages:
            if message["app"] == "WhatsApp" and message["source_file"] == self.source_label and message["snapshot_id"] == self.snapshot:
                message["attachments"] = list(dict.fromkeys(message["attachments"] + relations.get(message["source_record"], [])))

    def sqlite_fragments(self, path, app):
        data = path.read_bytes()
        if len(data) < 100 or data[:16] != b"SQLite format 3\x00":
            return
        page_size = int.from_bytes(data[16:18], "big")
        page_size = 65536 if page_size == 1 else page_size
        if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
            self.remark("SQLITE_PAGE_SIZE_INVALID", self.source_label)
            return
        page_count = len(data) // page_size
        freelist = int.from_bytes(data[32:36], "big")
        seen = set()
        pages = []
        while freelist and len(seen) < page_count:
            if freelist in seen or freelist > page_count:
                self.remark("SQLITE_FREELIST_INVALID", self.source_label)
                break
            seen.add(freelist)
            start = (freelist - 1) * page_size
            trunk = data[start:start + page_size]
            count = int.from_bytes(trunk[4:8], "big")
            if count > (page_size - 8) // 4:
                break
            for n in range(count):
                page = int.from_bytes(trunk[8 + 4*n:12 + 4*n], "big")
                if 0 < page <= page_count and page not in seen:
                    seen.add(page)
                    pages.append((page, data[(page - 1)*page_size:page*page_size]))
            # Unused trunk bytes can still retain strings, but not page pointers.
            pages.append((freelist, trunk[8 + 4*count:]))
            freelist = int.from_bytes(trunk[:4], "big")
        count = 0
        for page, payload in pages:
            # Only human-readable UTF-8 spans; no guessed chat IDs/authors/dates.
            for match in re.finditer(rb"(?:[\x20-\x7e]|[\xc2-\xf4][\x80-\xbf]+){12,}", payload):
                try:
                    text = match.group().decode("utf-8").strip()
                except UnicodeDecodeError:
                    continue
                if not text or not any(c.isalpha() for c in text):
                    continue
                self.message(app, text, "fragment", source_record=f"freelist:page={page}:offset={match.start()}",
                             confidence="fragment_only", relationships_unknown=True)
                count += 1
                if count >= 10000:
                    self.remark("FRAGMENT_LIMIT", self.source_label)
                    return

    def sqlite_wal_history(self, path):
        wal = Path(str(path) + "-wal")
        if not wal.exists() or wal.stat().st_size > MAX_DB:
            return
        raw = wal.read_bytes()
        if len(raw) < 32:
            self.remark("WAL_INVALID", self.source_label)
            return
        magic, version, page_size, sequence, salt1, salt2, c1, c2 = struct.unpack(">8I", raw[:32])
        if magic not in (0x377f0682, 0x377f0683) or version != 3007000 or not 512 <= page_size <= 65536 or page_size & (page_size-1):
            self.remark("WAL_INVALID", self.source_label)
            return
        order = "<" if magic == 0x377f0682 else ">"
        def checksum(block, a=0, b=0):
            words = struct.unpack(order + str(len(block)//4) + "I", block)
            for n in range(0, len(words), 2):
                a = (a + words[n] + b) & 0xffffffff
                b = (b + words[n + 1] + a) & 0xffffffff
            return a, b
        if checksum(raw[:24]) != (c1, c2):
            self.remark("WAL_CHECKSUM_INVALID", self.source_label)
            return
        if (len(raw) - 32) % (24 + page_size):
            self.remark("WAL_INCOMPLETE_TAIL", self.source_label)
        base = bytearray(path.read_bytes())
        if len(base) < 100 or int.from_bytes(base[16:18], "big") not in (page_size, 1 if page_size == 65536 else page_size):
            self.remark("WAL_DATABASE_MISMATCH", self.source_label)
            return
        commits = []
        count = 0
        for offset in range(32, len(raw) - 24 - page_size + 1, 24 + page_size):
            header = raw[offset:offset+24]
            page, size, s1, s2, a, b = struct.unpack(">6I", header)
            payload = raw[offset+24:offset+24+page_size]
            if not page or page > MAX_DB//page_size or (s1, s2) != (salt1, salt2):
                self.remark("WAL_FRAME_INVALID", self.source_label)
                break
            c1, c2 = checksum(header[:8] + payload, c1, c2)
            if (c1, c2) != (a, b):
                self.remark("WAL_CHECKSUM_INVALID", self.source_label)
                break
            end = page * page_size
            if end > len(base):
                base.extend(b"\x00" * (end - len(base)))
            base[(page-1)*page_size:end] = payload
            if size:
                if size * page_size > MAX_DB:
                    break
                snapshot = self.work / f"wal-{digest(path)[:12]}-{count}.db"
                snapshot.write_bytes(base[:size*page_size])
                commits.append(snapshot)
                count += 1
                if count >= 50:
                    self.remark("WAL_HISTORY_LIMIT", self.source_label)
                    break
        if commits:
            self.remark("WAL_CHECKED_COMMITS", self.source_label, commits=len(commits))
            old = self.snapshot
            for n, snapshot in enumerate(commits[:-1]):
                self.snapshot = f"{old}:wal:{n}"
                try:
                    self.sqlite_whatsapp(snapshot, "previous", False)
                except sqlite3.DatabaseError:
                    self.remark("WAL_SNAPSHOT_INCOMPLETE", self.source_label)
            self.snapshot = old

    def signal(self, path, modern=False, media_root=None):
        path = Path(path)
        origin_path = path / "main" if modern else path
        self.current_origin = self.origins.get(str(origin_path.resolve()), {})
        self.source_label = self.current_origin.get("OriginalPath") or str(path)
        self.snapshot = digest(origin_path)
        if modern:
            self.snapshot = hashlib.sha256((self.snapshot + digest(path / "metadata")).encode()).hexdigest()
        name = "SignalModernHelper.exe" if modern else "SignalLegacyHelper.exe"
        helper = self.tools_dir / "signal" / name if self.tools_dir else None
        if helper is None or not helper.exists():
            self.remark("SIGNAL_HELPER_UNAVAILABLE", path)
            return
        secret = self.secrets.get("signal_key")
        if not secret:
            self.remark("SIGNAL_KEY_REQUIRED", path)
            return
        destination = self.work / f"signal-{hashlib.sha256(str(path).encode()).hexdigest()[:12]}"
        request = {"protocol": 1, "operation": "import", "source": str(path), "destination": str(destination), "secret": secret}
        if media_root:
            request["media_root"] = str(media_root)
        completed = subprocess.run([str(helper)], input=json.dumps(request).encode("utf-8"), stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        validated = False
        failure_code = "SIGNAL_IMPORT_FAILED"
        try:
            for line in completed.stdout.decode("utf-8").splitlines():
                item = json.loads(line)
                if (item.get("event") or item.get("type")) == "result":
                    if item.get("status") in ("complete", "partial") and completed.returncode == 0:
                        validated = True
                        if item.get("status") == "partial":
                            self.remark("SIGNAL_PARTIAL_DATA", path, warnings=item.get("warnings", 0))
                    else:
                        failure_code = {"AUTH_FAILED": "SIGNAL_AUTHENTICATION_FAILED",
                                        "UNSUPPORTED_VERSION": "SIGNAL_VERSION_UNSUPPORTED",
                                        "KEY_REQUIRED": "SIGNAL_KEY_REQUIRED",
                                        "SECRET_REQUIRED": "SIGNAL_KEY_REQUIRED"}.get(item.get("code"), "SIGNAL_IMPORT_FAILED")
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        messages = destination / "messages.jsonl"
        if not validated or not messages.exists():
            self.remark(failure_code, path)
            return
        for line in messages.read_text(encoding="utf-8").splitlines():
            m = json.loads(line)
            attachments = [x for r in m.get("attachments", []) if (x := self.attachment(r, destination))]
            self.message("Signal", m.get("text", ""), m.get("evidence_kind", "backup"),
                         chat_id=m.get("chat_id"), sender_id=m.get("sender_id"), sender_name=m.get("sender_name"),
                         timestamp=utc_timestamp(m.get("timestamp")), message_id=None if modern else m.get("message_id"),
                         source_record=m.get("source_record"), attachments=attachments,
                         snapshot_id=m.get("snapshot_id") or self.snapshot)
        self.extracted_roots.append((destination, str(path)))

    def scan_file(self, path, label=None):
        if str(path.resolve()) in self.handled:
            return
        self.handled.add(str(path.resolve()))
        self.current_origin = self.origins.get(str(path.resolve()), {})
        self.source_label = self.current_origin.get("OriginalPath") or label or str(path)
        size = path.stat().st_size
        self.source_count += 1
        self.snapshot = digest(path)
        emit("progress", phase="scan", files=self.source_count, messages=len(self.messages), photos=len(self.photos))
        self.sources.append({"source": self.source_label, "sha256": self.snapshot, "size": size,
                             "status": "copied_input", "source_id": self.current_origin.get("Id"),
                             "relative_path": self.current_origin.get("RelativePath")})
        if path.name.lower().endswith(".partial") and self.current_origin.get("Status") != "complete":
            self.remark("INCOMPLETE_SOURCE", self.source_label)
            return
        name = path.name.lower()
        try:
            if name.endswith((".crypt12", ".crypt14", ".crypt15")):
                if self.telegram_only:
                    return
                decoded = self.decrypt_whatsapp(path)
                self.sqlite_whatsapp(decoded, media_base=path.parent)
                return
            if name.endswith(".backup"):
                if self.telegram_only:
                    return
                self.signal(path)
                return
            if name.endswith(".zip"):
                extraction = self.work / f"zip-{self.snapshot[:16]}"
                extraction.mkdir()
                safe_unzip(path, extraction)
                if self.current_origin:
                    for member in files_under(extraction):
                        relative = member.relative_to(extraction).as_posix()
                        self.origins[str(member.resolve())] = {**self.current_origin,
                            "OriginalPath": f"{self.source_label}!/{relative}",
                            "RelativePath": f"{self.current_origin.get('RelativePath', path.name)}!/{relative}"}
                self.extracted_roots.append((extraction, self.source_label))
                return
            with path.open("rb") as f:
                magic = f.read(32)
            if magic.startswith(b"SQLite format 3\x00"):
                if self.telegram_only:
                    from telegram_auto import import_database
                    import_database(self, path)
                else:
                    self.sqlite_whatsapp(path)
            elif size <= MAX_TEXT:
                if name.endswith(".json"):
                    self.telegram_json(path)
                elif name.endswith((".html", ".htm")):
                    self.telegram_html(path)
                elif name.endswith(".txt"):
                    if not self.telegram_only:
                        self.whatsapp_text(path)
            self.scan_images(path)
        except RecoveryError as e:
            self.remark(e.code, self.source_label)
        except (json.JSONDecodeError, UnicodeError, sqlite3.DatabaseError, zipfile.BadZipFile, plistlib.InvalidFileException):
            self.remark("SOURCE_FORMAT_INVALID", self.source_label)
        except (OSError, ValueError, KeyError, TypeError):
            self.remark("SOURCE_UNREADABLE", self.source_label)

    def scan_tree(self, root, label=None):
        root = Path(root)
        if root.is_dir() and (root / "Manifest.plist").exists() and (root / "Manifest.db").exists():
            try:
                self.iphone_backup(root)
            except RecoveryError as e:
                self.remark(e.code, label or root)
            return
        if root.is_dir() and (root / "main").is_file() and (root / "metadata").is_file():
            if self.telegram_only:
                return
            self.signal(root, modern=True, media_root=root.parent / "files")
            return
        if root.is_dir():
            snapshots = [d for d in root.iterdir() if d.is_dir() and not reparse(d)
                         and (d / "main").is_file() and (d / "metadata").is_file()]
            if snapshots:
                if self.telegram_only:
                    return
                for snapshot in sorted(snapshots):
                    self.signal(snapshot, modern=True, media_root=root / "files")
                # Shared media still participates in generic image discovery.
                if (root / "files").is_dir():
                    for path in files_under(root / "files"):
                        self.scan_file(path, f"{label or root}/files/{path.relative_to(root / 'files').as_posix()}")
                return
        if root.is_dir():
            for child in sorted(root.iterdir()):
                if reparse(child):
                    continue
                child_label = f"{label}/{child.name}" if label else None
                if child.is_dir():
                    self.scan_tree(child, child_label)
                elif child.is_file():
                    self.scan_file(child, child_label)
        else:
            self.scan_file(root, label)

    def acquisition_input(self):
        manifest = self.original_source.parent / "acquisition.json"
        if self.original_source.name.lower() != "snapshot" or not manifest.is_file():
            return self.original_source
        data = json.loads(manifest.read_text(encoding="utf-8-sig"))
        records = data.get("Files")
        if not isinstance(records, list):
            raise RecoveryError("ACQUISITION_MANIFEST_INVALID")
        target = self.work / "validated-input"
        target.mkdir()
        seen = set()
        for record in records:
            if record.get("Status") != "complete":
                self.remark("ACQUISITION_INCOMPLETE_FILE", record.get("OriginalPath"))
                continue
            try:
                rel = safe_relative(record["LocalPath"])
                src = self.original_source.parent.joinpath(*rel.parts)
                if not within(src, self.original_source) or not src.is_file() or reparse(src):
                    raise RecoveryError("ACQUISITION_PATH_INVALID")
                expected = record.get("Sha256", "")
                if not re.fullmatch(r"[0-9a-fA-F]{64}", expected) or digest(src).lower() != expected.lower():
                    raise RecoveryError("ACQUISITION_HASH_MISMATCH")
                relative = src.relative_to(self.original_source)
                dest = target / relative
                token = str(dest).casefold()
                if token in seen:
                    raise RecoveryError("ACQUISITION_PATH_COLLISION")
                seen.add(token)
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.link(src, dest)
                except OSError:
                    shutil.copyfile(src, dest)
                self.origins[str(dest.resolve())] = record
            except (KeyError, RecoveryError, OSError) as error:
                self.remark(error.code if isinstance(error, RecoveryError) else "ACQUISITION_FILE_INVALID", record.get("OriginalPath"))
        return target

    def publish(self):
        messages = self.output / "messages.jsonl"
        with messages.open("w", encoding="utf-8", newline="\n") as f:
            for m in self.messages:
                f.write(json.dumps(m, ensure_ascii=False) + "\n")
        (self.output / "photo-metadata.json").write_text(json.dumps({"photos": list(self.photos.values())}, ensure_ascii=False, indent=2), encoding="utf-8")
        (self.output / "attachment-metadata.json").write_text(json.dumps({"attachments": list(self.attachments.values())}, ensure_ascii=False, indent=2), encoding="utf-8")
        (self.output / "sources.json").write_text(json.dumps({"protocol": 1, "sources": self.sources}, ensure_ascii=False, indent=2), encoding="utf-8")
        con = sqlite3.connect(self.output / "chat-index.sqlite")
        con.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, app TEXT, chat_id TEXT, sender TEXT, timestamp TEXT, evidence TEXT, text TEXT, json TEXT)")
        con.execute("CREATE VIRTUAL TABLE search USING fts5(text,app,sender,content='messages',content_rowid='id')")
        for n, m in enumerate(self.messages, 1):
            con.execute("INSERT INTO messages VALUES(?,?,?,?,?,?,?,?)", (n, m["app"], str(m["chat_id"]) if m["chat_id"] is not None else None,
                         m["sender_name"] or m["sender_id"], m["timestamp"], m["evidence_kind"], m["text"], json.dumps(m, ensure_ascii=False)))
        con.execute("INSERT INTO search(search) VALUES('rebuild')")
        con.commit()
        con.close()
        self.write_html()
        self.write_photos()

    def write_html(self):
        payload = json.dumps(self.messages, ensure_ascii=False).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
        script = """const data=JSON.parse(document.getElementById('data').textContent);let page=0;const size=100;
const labels={export:'из экспорта',backup:'из резервной копии',previous:'предыдущая версия',fragment:'текстовый фрагмент'};
function draw(){const q=document.getElementById('q').value.toLocaleLowerCase();const cat=document.getElementById('cat').value;
const list=data.filter(m=>(!cat||m.evidence_kind===cat)&&[m.text,m.sender_name,m.sender_id,m.app,m.chat_name,m.chat_id].some(x=>String(x??'').toLocaleLowerCase().includes(q)));
page=Math.max(0,Math.min(page,Math.ceil(list.length/size)-1));const root=document.getElementById('messages');root.replaceChildren();
for(const m of list.slice(page*size,(page+1)*size)){const a=document.createElement('article');const h=document.createElement('strong');h.textContent=[m.app,m.chat_name??m.chat_id??'Чат неизвестен',m.sender_name??m.sender_id??'Автор неизвестен',m.timestamp??m.timestamp_raw??'Дата неизвестна'].join(' · ');a.append(h);
const b=document.createElement('small');b.textContent=labels[m.evidence_kind]+' · '+(m.source_file??'')+' · '+(m.source_record??'')+(m.record_kind==='memory_fragment'?' · Telegram, автор, дата и факт удаления не подтверждены':'')+(m.record_kind==='notification'?' · неполный текст уведомления':'');a.append(b);const t=document.createElement('pre');t.textContent=m.text;a.append(t);
for(const f of m.attachments??[]){if(!/^media\\/[a-f0-9]{64}\\.[a-z0-9]{1,12}$/.test(f))continue;const link=document.createElement('a');link.href=f;link.textContent='Открыть вложение';link.target='_blank';link.rel='noopener';link.download=f.split('/').pop();a.append(link);}root.append(a);}
document.getElementById('count').textContent=list.length+' сообщений · страница '+(page+1)+' из '+Math.max(1,Math.ceil(list.length/size));}
document.getElementById('q').oninput=()=>{page=0;draw()};document.getElementById('cat').onchange=()=>{page=0;draw()};document.getElementById('prev').onclick=()=>{page--;draw()};document.getElementById('next').onclick=()=>{page++;draw()};draw();"""
        script_hash = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        markup = """<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'sha256-@@HASH@@'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>Переписки — локальный архив</title><style>body{font:16px system-ui;max-width:1100px;margin:30px auto;padding:0 20px;background:#f7f8fb;color:#18233a}input,select,button{font:inherit;padding:10px;margin:4px}input{width:45%}article{background:white;padding:18px;margin:12px 0;border-radius:10px}small{display:block;color:#68768e;overflow-wrap:anywhere}pre{white-space:pre-wrap;font:inherit}a{display:block;margin:8px 0}</style>
<h1>Переписки</h1><p>Локальный архив доступных источников. Фрагменты не подтверждают автора, чат или факт удаления.</p><a href="Фотографии.html">Фотографии</a><input id="q" placeholder="Поиск текста, автора или чата"><select id="cat"><option value="">Все категории</option><option value="export">Из экспорта</option><option value="backup">Из резервной копии</option><option value="previous">Предыдущая версия</option><option value="fragment">Текстовые фрагменты</option></select>
<div id="count"></div><button id="prev">Назад</button><button id="next">Дальше</button><main id="messages"></main><script type="application/json" id="data">@@DATA@@</script><script>@@SCRIPT@@</script></html>"""
        (self.output / "Переписки.html").write_text(markup.replace("@@HASH@@", script_hash).replace("@@DATA@@", payload).replace("@@SCRIPT@@", script), encoding="utf-8")

    def write_photos(self):
        payload = json.dumps(list(self.photos.values()), ensure_ascii=False).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
        script = """const data=JSON.parse(document.getElementById('data').textContent);let page=0;const size=100;
function draw(){const q=document.getElementById('q').value.toLocaleLowerCase(),kind=document.getElementById('kind').value,w=Number(document.getElementById('w').value)||0,h=Number(document.getElementById('h').value)||0;
const list=data.filter(p=>(!kind||p.kind===kind)&&p.width>=w&&p.height>=h&&[p.format,p.path,...p.sources.map(s=>s.source_file)].some(x=>String(x??'').toLocaleLowerCase().includes(q)));
page=Math.max(0,Math.min(page,Math.ceil(list.length/size)-1));const root=document.getElementById('photos');root.replaceChildren();
for(const p of list.slice(page*size,(page+1)*size)){const a=document.createElement('article');const link=document.createElement('a');link.href=p.path;if(p.thumbnail){const img=document.createElement('img');img.src=p.thumbnail;img.loading='lazy';img.alt=p.format+' '+p.width+'×'+p.height;link.append(img);}else{link.textContent='Повреждённый кандидат: открыть оригинал';}a.append(link);const t=document.createElement('p');t.textContent=p.format+' · '+p.width+'×'+p.height+' · '+({photo:'фотография',thumbnail:'небольшое изображение / возможная миниатюра',embedded:'встроенное изображение',damaged:'повреждённый кандидат'}[p.kind]??p.kind);a.append(t);
const d=document.createElement('details'),s=document.createElement('summary');s.textContent='Источники: '+p.sources.length;d.append(s);for(const source of p.sources){const f=document.createElement('small');f.textContent=[source.source_file,source.source_record,source.source_id].filter(Boolean).join(' · ');d.append(f);}a.append(d);root.append(a);}document.getElementById('count').textContent=list.length+' изображений · страница '+(page+1)+' из '+Math.max(1,Math.ceil(list.length/size));}
for(const id of ['q','kind','w','h'])document.getElementById(id).oninput=()=>{page=0;draw()};document.getElementById('prev').onclick=()=>{page--;draw()};document.getElementById('next').onclick=()=>{page++;draw()};draw();"""
        script_hash = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        markup = """<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; script-src 'sha256-@@HASH@@'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>Фотографии</title><style>body{font:16px system-ui;padding:24px;background:#f7f8fb;color:#18233a}main{display:flex;flex-wrap:wrap;gap:14px}article{width:280px;background:white;padding:15px;overflow-wrap:anywhere}img{max-width:280px;max-height:220px}small{display:block;color:#68768e;margin:6px 0}input,select,button{font:inherit;padding:9px;margin:4px}input[type=number]{width:100px}</style>
<h1>Фотографии</h1><a href="Переписки.html">Переписки</a><p>Проверенные изображения и отдельные повреждённые кандидаты. Оригиналы сохранены в папке media.</p>
<input id="q" placeholder="Поиск по источнику, имени или формату"><select id="kind"><option value="">Все виды</option><option value="photo">Фотографии</option><option value="thumbnail">Небольшие / миниатюры</option><option value="embedded">Встроенные</option><option value="damaged">Повреждённые кандидаты</option></select><label>Ширина от <input id="w" type="number" min="0"></label><label>Высота от <input id="h" type="number" min="0"></label>
<div id="count"></div><button id="prev">Назад</button><button id="next">Дальше</button><main id="photos"></main><script type="application/json" id="data">@@DATA@@</script><script>@@SCRIPT@@</script></html>"""
        (self.output / "Фотографии.html").write_text(markup.replace("@@HASH@@", script_hash).replace("@@DATA@@", payload).replace("@@SCRIPT@@", script), encoding="utf-8")

    def run(self, photos_only=False):
        if not self.source.exists():
            raise RecoveryError("SOURCE_NOT_FOUND")
        if not photos_only and within(self.output, self.source if self.source.is_dir() else self.source.parent):
            raise RecoveryError("DESTINATION_INSIDE_SOURCE")
        if self.output.exists() and any(self.output.iterdir()):
            raise RecoveryError("DESTINATION_NOT_EMPTY")
        if self.scratch:
            expected_scratch = Path(str(self.output) + ".work").resolve()
            if self.scratch != expected_scratch or (not photos_only and within(self.scratch, self.source if self.source.is_dir() else self.source.parent)):
                raise RecoveryError("SCRATCH_PATH_INVALID")
            if self.scratch.exists() and (reparse(self.scratch) or any(self.scratch.iterdir())):
                raise RecoveryError("SCRATCH_NOT_EMPTY")
            self.scratch.mkdir(parents=True, exist_ok=True)
        self.output.mkdir(parents=True, exist_ok=True)
        for name in ("media", "previews"):
            (self.output / name).mkdir(exist_ok=True)
        (self.output / "job.incomplete").write_text('Import did not finish. Do not consider partial results authenticated.\n', encoding="utf-8")
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS
        try:
            import pillow_heif
            pillow_heif.register_heif_opener()
        except ImportError:
            self.remark("HEIF_RUNTIME_UNAVAILABLE")
        with tempfile.TemporaryDirectory(prefix="recovery-v3-", dir=self.scratch) as scratch:
            self.work = Path(scratch)
            if photos_only:
                # Do not rescan raw usb.dd or arbitrary run artifacts. Restrict
                # this operation to already recovered v2 photo candidates.
                roots = [self.source / "filesystem" / "files", self.source / "extra-photos"]
                roots.extend(self.source.glob("ntfs/*/data"))
                roots.extend(p for p in self.source.glob("files.*") if p.is_dir())
                for root in roots:
                    if root.exists():
                        for path in files_under(root):
                            self.source_label = str(path)
                            self.snapshot = digest(path)
                            self.scan_images(path)
            else:
                self.scan_tree(self.acquisition_input())
            n = 0
            while n < len(self.extracted_roots):
                root, label = self.extracted_roots[n]
                self.scan_tree(root, label)
                n += 1
            blocking = {"IOS_PASSWORD_REQUIRED", "IOS_PASSWORD_INCORRECT", "IOS_BACKUP_INVALID",
                        "IOS_MANIFEST_INVALID", "WHATSAPP_KEY_REQUIRED", "WHATSAPP_AUTHENTICATION_FAILED",
                        "WHATSAPP_KEY_FORMAT", "SIGNAL_KEY_REQUIRED", "SIGNAL_IMPORT_FAILED",
                        "SIGNAL_AUTHENTICATION_FAILED", "SIGNAL_HELPER_UNAVAILABLE", "SIGNAL_VERSION_UNSUPPORTED", "IOS_VERSION_UNSUPPORTED",
                        "IOS_FILE_DIGEST_MISMATCH", "IOS_FILE_SIZE_MISMATCH", "IOS_FILE_METADATA_INVALID"}
            failed_protected = any(x.get("code") in blocking for x in self.sources)
            if failed_protected and not self.messages and not self.photos:
                (self.output / "sources.json").write_text(json.dumps({"protocol": 1, "sources": self.sources}, ensure_ascii=False, indent=2), encoding="utf-8")
                return {"status": "error", "code": "AUTH_FAILED" if any(x.get("code") in
                         {"IOS_PASSWORD_INCORRECT", "IOS_FILE_DIGEST_MISMATCH", "WHATSAPP_AUTHENTICATION_FAILED", "SIGNAL_AUTHENTICATION_FAILED"}
                         for x in self.sources) else "SOURCE_UNAVAILABLE", "messages": 0, "media": 0,
                         "photos": 0, "destination": str(self.output)}
            self.publish()
        (self.output / "job.incomplete").unlink()
        errors = [x for x in self.sources if "code" in x]
        informational = {"HTML_CHAT_ID_UNKNOWN", "DATE_ORDER_UNKNOWN", "WHATSAPP_SCHEMA_ADAPTER",
                         "IOS_CACHE_NOT_IN_BACKUP", "IOS_UNENCRYPTED_EXTRACTED", "WAL_CHECKED_COMMITS"}
        partial = any(x.get("code") not in informational for x in errors)
        return {"status": "partial" if partial else "complete", "code": "PARTIAL_DATA" if partial else "OK",
                "messages": len(self.messages), "photos": sum(p["status"] == "decoded" for p in self.photos.values()),
                "photo_candidates": len(self.photos), "media": sum(1 for p in (self.output / "media").iterdir() if p.is_file()),
                "remarks": len(errors), "destination": str(self.output), "archive": str(self.output / "Переписки.html"),
                "photo_archive": str(self.output / "Фотографии.html"), "sources": str(self.output / "sources.json")}


def main():
    global emit
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    logging.disable(logging.CRITICAL)
    try:
        line = sys.stdin.readline(1024 * 1024)
        request = json.loads(line)
        if request.get("protocol") == 1 and request.get("operation") == "telegram_analyze":
            from telegram_auto import analyze, AutoError
            try:
                result = analyze(request, Importer, emit)
            except AutoError as error:
                emit("result", status="error", code=error.code)
                return 2
            emit("result", **result)
            return 2 if result["status"] == "error" else 0
        if request.get("protocol") == 1 and request.get("operation") == "search":
            from archive_search import search, SearchError
            try:
                result = search(request)
            except SearchError as error:
                emit("result", status="error", code=error.code)
                return 2
            emit("result", **result)
            return 0
        if request.get("protocol") != 1 or request.get("operation") not in ("scan", "photos"):
            raise RecoveryError("PROTOCOL_UNSUPPORTED")
        tools = Path(sys.executable).parent.parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2] / "tools"
        # All stdout/stderr generated by external parsers is captured and
        # discarded. Our controlled NDJSON emitter retains the original stream.
        original_stdout = sys.stdout
        def controlled_emit(event, **fields):
            original_stdout.write(json.dumps({"protocol": 1, "type": event, "event": event, **fields}, ensure_ascii=False) + "\n")
            original_stdout.flush()
        emit = controlled_emit
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            worker = Importer(request["source"], request["destination"], request.get("secrets"),
                              request.get("options", {}).get("deep", True), tools,
                              request.get("options", {}).get("scratch"))
            worker.telegram_only = True
            result = worker.run(request["operation"] == "photos")
        emit("result", **result)
        return 2 if result["status"] == "error" else 0
    except RecoveryError as e:
        emit("result", status="error", code=e.code)
        return 2
    except BaseException:
        emit("result", status="error", code="IMPORT_FAILED")
        return 3


if __name__ == "__main__":
    sys.exit(main())
