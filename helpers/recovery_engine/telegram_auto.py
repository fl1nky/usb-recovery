"""Bounded, offline discovery of readable Telegram exports and local archives.

Desktop tdata is an encrypted client cache, not an exported chat database. This
module never reads key_data, auth/session material or tries to unlock that cache.
Only recognized readable records and images enter the published archive. Every
parser runs against a verified temporary copy; original files remain untouched.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import struct
import tempfile
from typing import Iterable

MAX_FILES = 30_000
MAX_DEPTH = 10
MAX_ROOTS = 100
MAX_COPY_BYTES = 16 * 1024 * 1024 * 1024
MAX_SOURCE = 4 * 1024 * 1024 * 1024
MAX_TEXT = 128 * 1024 * 1024
MAX_RECORD = 4 * 1024 * 1024
MAX_MESSAGES = 300_000
MAX_NATIVE_THUMBNAILS = 10_000
MAX_NATIVE_THUMBNAIL_BYTES = 512 * 1024 * 1024
# These native Desktop files may contain account secrets. Never open or copy.
NATIVE_PRIVATE = {"key_data", "key_datas", "key_data0", "key_data1", "settings",
                  "settingss", "settings0", "settings1", "map", "maps", "map0", "map1"}
SKIP_DIRECTORIES = {".git", "node_modules", "__pycache__", "licenses", "rebuild"}


def _private_name(path):
    stem = Path(path).name.casefold().split(".", 1)[0]
    return stem in NATIVE_PRIVATE or re.fullmatch(r"[0-9a-f]{16}[s01]?", stem) is not None


class AutoError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _hash(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def _plain_path(value):
    path = Path(os.path.abspath(value))
    for item in (path, *path.parents):
        try:
            attributes = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(attributes.st_mode) or getattr(attributes, "st_file_attributes", 0) & 0x400:
            raise AutoError("TELEGRAM_REPARSE_SKIPPED")
    return path


def _within(path, root):
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
        return True
    except ValueError:
        return False


def known_roots(application_directory=None):
    """Inspect directory metadata only, never enumerate unrelated user folders."""
    home = Path.home()
    roaming = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
    local = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
    result = [(roaming / "Telegram Desktop/tdata", "desktop_cache"),
              (roaming / "Telegram Desktop UWP/tdata", "desktop_cache"),
              (local / "Telegram Desktop/tdata", "desktop_cache")]
    if application_directory:
        app = _plain_path(application_directory)
        # Only actual portable Telegram locations. Never scan developer tests,
        # vendor sources, or the recovery program's entire directory.
        for candidate in (app, app / "Telegram Desktop", app / "Telegram"):
            if (candidate / "Telegram.exe").is_file():
                result.append((candidate / "tdata", "desktop_cache"))
                result.append((candidate / "TelegramForcePortable/tdata", "desktop_cache"))
    result.extend([(home / "Downloads/Telegram Desktop", "telegram_files"),
                   (home / "Downloads/TelegramDesktop", "telegram_files"),
                   (home / "Documents/Telegram Desktop", "telegram_files"),
                   (Path("C:/Recovery-Results"), "archive")])
    for directory in (home / "Downloads", home / "Documents"):
        try:
            directory = _plain_path(directory)
            for child in directory.iterdir():
                if child.name.casefold().startswith(("chatexport", "chat export", "telegramexport", "telegram export")):
                    result.append((child, "export"))
        except (OSError, AutoError):
            pass
    packages = local / "Packages"
    try:
        packages = _plain_path(packages)
        for package in packages.iterdir():
            if "telegram" in package.name.casefold():
                # UWP app data is contained inside this package, not all Packages.
                for sub in ("LocalCache/Roaming/Telegram Desktop/tdata", "LocalCache/Roaming/Telegram Desktop UWP/tdata", "LocalState", "RoamingState"):
                    result.append((package / sub, "desktop_cache"))
    except (OSError, AutoError):
        pass
    return result[:MAX_ROOTS]


def _roots(request):
    options = request.get("options", {})
    explicit = options.get("roots")
    if explicit is None:
        return known_roots(options.get("application_directory"))
    if not isinstance(explicit, list) or len(explicit) > MAX_ROOTS:
        raise AutoError("TELEGRAM_ROOTS_INVALID")
    result = []
    for item in explicit:
        if isinstance(item, str):
            result.append((Path(item), "desktop_cache" if Path(item).name.lower() == "tdata" else "explicit"))
        elif isinstance(item, dict) and isinstance(item.get("path"), str):
            kind = item.get("kind", "explicit")
            if kind not in {"explicit", "dump", "desktop_cache", "archive", "export", "telegram_files"}:
                raise AutoError("TELEGRAM_ROOTS_INVALID")
            result.append((Path(item["path"]), kind))
        else:
            raise AutoError("TELEGRAM_ROOTS_INVALID")
    return result


def _timestamp(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        date = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.tzinfo is None:
            # Export timezone can be absent. This is a display ordering value,
            # not an assertion that an unknown timezone was UTC.
            date = date.replace(tzinfo=dt.timezone.utc)
        return date.timestamp()
    except ValueError:
        # Desktop HTML title usually has this explicit form, with timezone.
        for fmt in ("%d.%m.%Y %H:%M:%S UTC%z", "%d.%m.%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                date = dt.datetime.strptime(value, fmt)
                return date.replace(tzinfo=date.tzinfo or dt.timezone.utc).timestamp()
            except ValueError:
                pass
        return None


def _export_json(data):
    if not isinstance(data, dict) or data.get("app") not in (None, "Telegram"):
        return False
    chats = data.get("chats", {}).get("list") if isinstance(data.get("chats"), dict) else None
    if chats is None and isinstance(data.get("messages"), list):
        chats = [data]
    if not isinstance(chats, list):
        return False
    for chat in chats:
        if not isinstance(chat, dict) or not isinstance(chat.get("messages"), list):
            continue
        kind = chat.get("type")
        if kind in {"personal_chat", "private_group", "private_supergroup", "public_supergroup", "public_channel", "private_channel", "bot_chat", "saved_messages"}:
            return True
        if any(isinstance(m, dict) and m.get("app") in (None, "Telegram") and
               "id" in m and "date" in m and ("from_id" in m or "from" in m)
               for m in chat["messages"][:100]):
            return True
    return False


def _references(data):
    chats = data.get("chats", {}).get("list", []) if isinstance(data.get("chats"), dict) else []
    if isinstance(data.get("messages"), list):
        chats = [data]
    for chat in chats:
        if not isinstance(chat, dict):
            continue
        for message in chat.get("messages", []):
            if isinstance(message, dict):
                for key in ("photo", "file"):
                    if isinstance(message.get(key), str):
                        yield message[key]


def _safe_reference(reference):
    if not isinstance(reference, str) or not reference or "\x00" in reference or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", reference):
        return None
    value = reference.replace("\\", "/")
    if value.startswith("/") or any(p in ("", ".", "..") for p in value.split("/")) or ":" in value:
        return None
    return Path(*value.split("/"))


class Analyzer:
    def __init__(self, request, importer, emit):
        self.request = request
        self.emit = emit
        self.output = _plain_path(request.get("destination", ""))
        if not isinstance(request.get("destination"), str) or not request["destination"]:
            raise AutoError("DESTINATION_INVALID")
        if self.output.exists() and (not self.output.is_dir() or any(self.output.iterdir())):
            raise AutoError("DESTINATION_NOT_EMPTY")
        self.scratch = _plain_path(str(self.output) + ".work")
        scratch_requested = request.get("options", {}).get("scratch")
        if scratch_requested and _plain_path(scratch_requested) != self.scratch:
            raise AutoError("SCRATCH_PATH_INVALID")
        if self.scratch.exists() and (not self.scratch.is_dir() or any(self.scratch.iterdir())):
            raise AutoError("SCRATCH_NOT_EMPTY")
        self.importer_type = importer
        self.worker = None
        self.seen = set()
        self.copied = {}
        self.files = 0
        self.bytes = 0
        self.counts = dict(discovered_sources=0, readable_sources=0, encrypted_sources=0, blocked_sources=0)
        self.warnings = []
        self.copy_records = []
        self.notifications = 0
        self.notification_identities = {}
        self.history_snapshot = None
        self.current_wal = None
        self.recover_deleted = request.get("options", {}).get("recover_deleted", True) is True
        self.deleted_current_verified = True
        self.stop = False
        from text_match import Matcher, MatchError
        try:
            self.fragment_matcher = Matcher(request.get("options", {}).get("fragment_query", ""), request.get("options", {}).get("query_mode", "literal"))
        except MatchError as error:
            raise AutoError(error.code) from None
        self.fragments = 0
        self.explicit = request.get("options", {}).get("roots") is not None
        self.scan_fragments = self.explicit and request.get("options", {}).get("scan_fragments") is True

    def remark(self, code, source=None, **details):
        if code not in self.warnings:
            self.warnings.append(code)
        self.worker.remark(code, source, **details)

    def copy(self, source, target):
        source = _plain_path(source)
        if str(source).casefold() in self.copied:
            # Each parser requires its own relative sibling layout. Reuse only
            # a verified working copy, never create a hardlink to an original.
            previous = self.copied[str(source).casefold()]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(previous, target)
            self.worker.origins[str(target.resolve())] = self.worker.origins[str(previous.resolve())]
            return target
        before = source.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SOURCE or self.bytes + before.st_size > MAX_COPY_BYTES:
            raise AutoError("TELEGRAM_SOURCE_LIMIT")
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = Path(str(target) + ".partial")
        h = hashlib.sha256()
        copied_bytes = 0
        with source.open("rb") as inp, partial.open("xb") as out:
            while chunk := inp.read(1024 * 1024):
                copied_bytes += len(chunk)
                if copied_bytes > before.st_size:
                    raise AutoError("TELEGRAM_SOURCE_CHANGED")
                h.update(chunk)
                out.write(chunk)
        after = source.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or h.hexdigest() != _hash(source):
            partial.unlink(missing_ok=True)
            raise AutoError("TELEGRAM_SOURCE_CHANGED")
        partial.replace(target)
        self.bytes += before.st_size
        record = {"Id": hashlib.sha256(str(source).encode()).hexdigest(), "OriginalPath": str(source),
                  "RelativePath": source.name, "Size": before.st_size, "Modified": before.st_mtime_ns,
                  "Sha256": h.hexdigest(), "Status": "complete"}
        self.worker.origins[str(target.resolve())] = record
        self.copy_records.append(record)
        self.copied[str(source).casefold()] = target
        return target

    def walk(self, root):
        if root.is_file():
            yield root
            return
        stack = [(root, 0)]
        while stack and not self.stop:
            current, depth = stack.pop()
            try:
                items = sorted(current.iterdir(), key=lambda x: x.name.casefold())
            except OSError:
                self.counts["blocked_sources"] += 1
                self.remark("TELEGRAM_DIRECTORY_UNAVAILABLE", current)
                continue
            for item in items:
                try:
                    _plain_path(item)
                    if _within(item, self.output) or _within(item, self.scratch):
                        continue
                    if item.is_dir():
                        if item.name.casefold() in SKIP_DIRECTORIES or item.name.casefold().endswith(".work"):
                            continue
                        if depth < (32 if self.explicit else MAX_DEPTH):
                            stack.append((item, depth + 1))
                        else:
                            self.remark("TELEGRAM_DEPTH_LIMIT", item)
                    elif item.is_file():
                        yield item
                except (OSError, AutoError):
                    self.counts["blocked_sources"] += 1
                    self.remark("TELEGRAM_PATH_UNAVAILABLE", item)

    def references(self, references, original_base, copied_base):
        for reference in dict.fromkeys(references):
            relative = _safe_reference(reference)
            if relative is None:
                continue
            source, target = original_base / relative, copied_base / relative
            if _private_name(source):
                self.remark("TELEGRAM_PRIVATE_REFERENCE_SKIPPED", source)
                continue
            if not _within(source, original_base):
                continue
            try:
                if source.is_file():
                    self.copy(source, target)
            except (OSError, AutoError):
                self.remark("ATTACHMENT_UNAVAILABLE", source)

    def canonical_records(self, path, original):
        # Published archives may contain other applications. Decode only the
        # allow-listed Telegram display/provenance fields, excluding secrets.
        from archive_search import _normalized
        with path.open("rb") as source:
            number = 0
            while raw := source.readline(MAX_RECORD + 1):
                number += 1
                if len(raw) > MAX_RECORD:
                    self.remark("TELEGRAM_RECORD_LIMIT", original)
                    while raw and not raw.endswith(b"\n"):
                        raw = source.readline(MAX_RECORD + 1)
                    continue
                try:
                    value = _normalized(json.loads(raw))
                except (ValueError, UnicodeError):
                    value = None
                if value and value["app"] == "Telegram":
                    self.canonical_message(value, path, original, f"line:{number}")
                if len(self.worker.messages) >= MAX_MESSAGES:
                    self.remark("TELEGRAM_MESSAGE_LIMIT", original)
                    self.stop = True
                    return

    def canonical_message(self, value, copied, original, record):
        refs = value.pop("attachments", [])
        self.references(refs, original.parent, copied.parent)
        attachments = [item for ref in refs if (item := self.worker.attachment(ref, copied.parent))]
        # All published provenance points to the real source, never a deleted
        # temp path; original record provenance remains available separately.
        text = value.pop("text")
        evidence = value.pop("evidence_kind")
        previous_provenance = {name: value.get(name) for name in ("source_file", "source_record", "snapshot_id", "source_sha256") if value.get(name) is not None}
        for field in ("app", "snapshot_id", "sources", "source_file", "source_record", "source_id", "source_sha256", "original_relative_path"):
            value.pop(field, None)
        self.message(text, evidence, source_record=record, previous_provenance=previous_provenance,
                     attachments=attachments, **value)

    def message(self, text, evidence, **fields):
        if self.history_snapshot:
            history = self.history_snapshot
            evidence = "previous"
            fields.update(previous_version=True, wal_commit_frame=history["commit_frame"],
                wal_proof=history["proof"], wal_db_sha256=history["db_sha256"],
                wal_sha256=history["wal_sha256"], wal_snapshot_sha256=history["sha256"])
            fields["source_record"] = str(fields.get("source_record") or "record") + "@wal_commit:" + str(history["commit_frame"])
        elif self.current_wal:
            fields.update(wal_commit_frame=self.current_wal.get("latest_commit_frame"),
                wal_proof="validated_wal_commit", wal_sha256=self.current_wal.get("wal_sha256"),
                wal_db_sha256=self.current_wal.get("db_sha256"))
        if fields.get("record_kind") != "notification":
            return self.worker.message("Telegram", text, evidence, **fields)
        # A notification preview cannot replace a verified full export just
        # because its visible text happens to be identical. Deduplicate IDs
        # separately within this explicitly marked evidence class.
        history_ids = self.worker.identities
        self.worker.identities = self.notification_identities
        try:
            return self.worker.message("Telegram", text, evidence, **fields)
        finally:
            self.worker.identities = history_ids

    def sqlite(self, copied, original):
        connection = sqlite3.connect(copied.as_uri() + ("?mode=ro&immutable=1" if self.history_snapshot else "?mode=ro"), uri=True)
        connection.enable_load_extension(False)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        operations = 0
        def bounded_sqlite():
            nonlocal operations
            operations += 10000
            return int(self.stop or operations > 50_000_000)
        connection.set_progress_handler(bounded_sqlite, 10000)
        try:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise AutoError("TELEGRAM_SQLITE_INVALID")
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.last_native_database = bool({"messages_v2", "messages_topics", "unread_push_messages"} & tables)
            if "messages" in tables:
                cols = {row[1] for row in connection.execute("PRAGMA table_info(messages)")}
                if {"id", "app", "json"} <= cols:
                    from archive_search import _normalized
                    for record, raw in connection.execute("SELECT id, CASE WHEN length(json)<=? THEN json ELSE NULL END FROM messages WHERE app=? ORDER BY id", (MAX_RECORD, "Telegram")):
                        try:
                            value = _normalized(json.loads(raw)) if isinstance(raw, str) else None
                        except (ValueError, UnicodeError):
                            value = None
                        if value and value["app"] == "Telegram":
                            self.canonical_message(value, copied, original, f"messages.id:{record}")
                        if len(self.worker.messages) >= MAX_MESSAGES:
                            self.remark("TELEGRAM_MESSAGE_LIMIT", original)
                            self.stop = True
                            break
                    return True
            if "unread_push_messages" in tables:
                cols = {row[1] for row in connection.execute("PRAGMA table_info(unread_push_messages)")}
                if {"uid", "mid", "date", "fm"} <= cols:
                    # Official Android fm is messageText.toString(), a saved
                    # push-notification preview. It is not proof of full chat
                    # history or a known sender. Reactions are kept separate.
                    reaction = "is_reaction" if "is_reaction" in cols else "0"
                    for uid, mid, date, text, is_reaction in connection.execute(
                            f"SELECT uid,mid,date,CASE WHEN length(fm)<=? THEN fm ELSE NULL END,{reaction} FROM unread_push_messages ORDER BY date DESC", (MAX_RECORD,)):
                        if not isinstance(text, str) or not text or is_reaction:
                            continue
                        timestamp = None
                        try:
                            if isinstance(date, (int, float)) and 0 <= date <= 32_503_680_000:
                                timestamp = dt.datetime.fromtimestamp(date, dt.timezone.utc).isoformat()
                        except (ValueError, OSError, OverflowError):
                            pass
                        self.message(text, "backup", chat_id=uid, message_id=mid,
                            timestamp=timestamp, sender_id=None, sender_name=None,
                            source_record=f"unread_push_messages(uid={uid},mid={mid})", record_kind="notification",
                            completeness="saved_notification_preview")
                        self.notifications += 1
                        if len(self.worker.messages) >= MAX_MESSAGES:
                            self.remark("TELEGRAM_MESSAGE_LIMIT", original)
                            self.stop = True
                            break
                    self.remark("TELEGRAM_NOTIFICATION_PREVIEWS", original)
            if {"messages_v2", "messages_topics"} & tables:
                self.native_messages(connection, tables, original)
                if not self.history_snapshot and getattr(self, "recover_deleted", True) and self.deleted_current_verified:
                    self.deleted_records(copied, connection, original)
                return True
            if {"dialogs", "unread_push_messages"} & tables:
                return True
            self.remark("TELEGRAM_SQLITE_SCHEMA_UNSUPPORTED", original)
            return False
        finally:
            connection.close()

    def native_messages(self, connection, tables, original):
        """Read typed records only when their DB keys agree with TL fields.

        Secret-chat IDs, unknown layouts and mismatched keys are unsupported.
        Absent names/senders and unavailable attachments remain unknown.
        """
        from telegram_tl import parse_message, TelegramTlError
        source_label = self.worker.source_label or str(original)
        identity = "telegram-db:" + hashlib.sha256(os.path.normcase(os.path.abspath(source_label)).encode("utf-8")).hexdigest()
        rejected, accepted, errors = 0, 0, {}
        for table in ("messages_v2", "messages_topics"):
            if table not in tables:
                continue
            columns = {row[1] for row in connection.execute("PRAGMA table_info(" + table + ")")}
            if not {"mid", "uid", "date", "data"} <= columns:
                self.remark("TELEGRAM_NATIVE_SCHEMA_UNSUPPORTED", original, table=table)
                continue
            topic = ",topic_id" if "topic_id" in columns else ""
            query = "SELECT mid,uid,date,CASE WHEN length(data)<=? THEN data ELSE NULL END" + topic
            query += " FROM " + table + " ORDER BY date DESC LIMIT ?"
            for row in connection.execute(query, (MAX_RECORD, MAX_MESSAGES + 1)):
                mid, uid, date, data = row[:4]
                try:
                    if not all(type(v) is int for v in (mid, uid, date)) or not isinstance(data, bytes):
                        raise TelegramTlError("TL_DB_ROW_INVALID")
                    value = parse_message(data)
                    if mid != value["id"] or date != value["date"]:
                        raise TelegramTlError("TL_DB_KEYS_MISMATCH")
                    peer, sender = value["peer"], value["from_peer"]
                    if peer["kind"] in ("chat", "channel"):
                        related = uid == -peer["id"]
                    elif value["out"] or sender is None:
                        related = uid > 0 and uid == peer["id"]
                    else:
                        related = uid > 0 and sender["kind"] == "user" and uid == sender["id"]
                    if not related:
                        raise TelegramTlError("TL_DB_DIALOG_MISMATCH")
                    media = value.get("media", {})
                    text = value["text"] or media.get("legacy_caption", "")
                    if not text and media.get("type") != "photo":
                        continue
                    timestamp = dt.datetime.fromtimestamp(date, dt.timezone.utc).isoformat() if date else None
                    record = f"{table}(uid={uid},mid={mid}" + (f",topic_id={row[4]}" if topic else "") + ")"
                    media_fields, attachments = self.native_photo(media, record, original)
                    self.message(text, "backup", chat_id=uid, message_id=mid,
                        sender_id=(sender["kind"] + ":" + str(sender["id"])) if sender else None,
                        sender_name=None, timestamp=timestamp, source_record=record,
                        identity_scope=identity, record_kind="tl_message", completeness=value["validation"],
                        native_constructor=value["constructor"], native_layer=value["layer"], application_confirmed=True,
                        native_tl_body_sha256=hashlib.sha256(data[:value["tl_bytes"]]).hexdigest(),
                        attachments=attachments, **media_fields)
                    self.confirmed_tl_bodies.add(hashlib.sha256(data[:value["tl_bytes"]]).hexdigest())
                    accepted += 1
                except (TelegramTlError, OverflowError, OSError, ValueError) as error:
                    rejected += 1
                    code = error.code if isinstance(error, TelegramTlError) else "TL_DB_DATE_INVALID"
                    errors[code] = errors.get(code, 0) + 1
                if len(self.worker.messages) >= MAX_MESSAGES:
                    self.remark("TELEGRAM_MESSAGE_LIMIT", original)
                    self.stop = True
                    break
            if self.stop:
                break
        if accepted:
            self.worker.remark("TELEGRAM_NATIVE_RECORDS_CHECKED", original, records=accepted)
        if rejected:
            self.remark("TELEGRAM_TL_HISTORY_UNSUPPORTED", original, rejected_records=rejected, reasons=errors)

    def residual_fragment(self, value, original, *, record_kind="sqlite_residual_fragment"):
        """Publish typed text without promoting its candidate IDs to a chat."""
        from memory_fragments import MAX_FRAGMENTS
        if self.fragments >= MAX_FRAGMENTS or len(self.worker.messages) >= MAX_MESSAGES:
            self.remark("MEMORY_FRAGMENT_LIMIT", original)
            return False
        text = value.pop("text")
        if self.fragment_matcher is not None and not self.fragment_matcher.matches(text):
            return
        self.worker.message("Telegram", text, "fragment", **value,
            record_kind=record_kind, completeness="typed_tl_body_without_table_or_account_context",
            source_record=f"sqlite-byte:{value['byte_offset']}:{value.get('sqlite_region', 'unattributed')}")
        self.fragments += 1

    def deleted_records(self, copied, connection, original):
        """Recover bounded non-current rows tied to a verified table leaf."""
        from sqlite_deleted import recover, DeletedError
        report = {}
        try:
            records = recover(copied, connection=connection,
                include_unattributed=getattr(self, "scan_fragments", False),
                cancel=lambda: self.stop, report=report)
        except DeletedError as error:
            self.remark("TELEGRAM_SQLITE_RESIDUALS_UNAVAILABLE", original, reason=error.code)
            return
        self.worker.remark("TELEGRAM_SQLITE_RESIDUALS_CHECKED", original, **report)
        if report.get("limited") or report.get("skipped_pages"):
            self.remark("TELEGRAM_SQLITE_RESIDUALS_INCOMPLETE", original)
        for item in records:
            if "row" in item:
                item.update(wal_sha256=report.get("wal_sha256"), wal_db_sha256=report.get("db_sha256"))
        self.pending_deleted_records.extend(records)

    def publish_deleted_records(self, records, original):
        source_label = self.worker.source_label or str(original)
        identity = "telegram-db:" + hashlib.sha256(os.path.normcase(os.path.abspath(source_label)).encode("utf-8")).hexdigest()
        for item in records:
            if self.stop:
                break
            if "row" not in item:
                self.residual_fragment(item, original)
                continue
            row, value = item.pop("row"), item.pop("value")
            sender = value["from_peer"]
            media = value.get("media", {})
            text = value["text"] or media.get("legacy_caption", "")
            if not text and media.get("type") != "photo":
                continue
            record = f"{item['table']}(uid={row['uid']},mid={row['mid']})@sqlite-page:{item['sqlite_page']}:byte:{item['sqlite_record_page_offset']}"
            body_hash = hashlib.sha256(row["data"][:value["tl_bytes"]]).hexdigest()
            key = ("Telegram", identity, "tl_message", row["uid"], row["mid"])
            matched = next((previous for previous in self.worker.identities.get(key, [])
                            if previous.get("native_tl_body_sha256") == body_hash), None)
            if matched is not None:
                # Exact typed bytes, row keys and account scope are already
                # represented by a complete committed snapshot. Preserve its
                # stronger historical proof and attach independent free-space
                # evidence rather than inventing a second chat message.
                matched["recovery_status"] = item["recovery_status"]
                matched["deletion_interpretation"] = item["deletion_interpretation"]
                matched["deleted"] = None
                provenance = {**item, "source_record": record, "source_file": source_label,
                              "snapshot_id": self.worker.snapshot}
                matched.setdefault("residual_sources", []).append(provenance)
                continue
            media_fields, attachments = self.native_photo(media, record, original)
            evidence = "previous" if item["recovery_status"] == "previous_version_residual" else "backup"
            self.message(text, evidence, chat_id=row["uid"], message_id=row["mid"],
                sender_id=(sender["kind"] + ":" + str(sender["id"])) if sender else None,
                sender_name=None, timestamp=dt.datetime.fromtimestamp(row["date"], dt.timezone.utc).isoformat() if row["date"] else None,
                source_record=record, identity_scope=identity, record_kind="sqlite_deleted_record",
                completeness=value["validation"], native_constructor=value["constructor"],
                native_layer=value["layer"], application_confirmed=True,
                native_tl_body_sha256=hashlib.sha256(row["data"][:value["tl_bytes"]]).hexdigest(),
                attachments=attachments, **item, **media_fields)
            self.confirmed_tl_bodies.add(hashlib.sha256(row["data"][:value["tl_bytes"]]).hexdigest())
            if len(self.worker.messages) >= MAX_MESSAGES:
                self.stop = True
                self.remark("TELEGRAM_MESSAGE_LIMIT", original)
                break

    def native_photo(self, media, record, original):
        """Link only cached image bytes embedded in this validated TL record.

        File locations/access hashes/references and the Android attachPath are
        never used to open another file or access the network. Stripped/path
        encodings are metadata, not complete image attachments.
        """
        if media.get("type") != "photo":
            return {}, []
        photo = media.get("photo", {})
        attachments = []
        snapshot = self.history_snapshot
        history_fields = {name: snapshot[key] for name, key in (
            ("wal_commit_frame", "commit_frame"), ("wal_sha256", "wal_sha256"),
            ("wal_snapshot_sha256", "sha256"))} if snapshot else {}
        if snapshot:
            record += "@wal_commit:" + str(snapshot["commit_frame"])
        for index, size in enumerate(photo.get("sizes", [])):
            if size.get("kind") != "cached" or not size.get("content"):
                continue
            content = size["content"]
            digest = hashlib.sha256(content).hexdigest()
            # Decoding inline photos is a new path in addition to generic
            # media scans. Bound both unique bytes and decoder invocations;
            # duplicate bytes reuse the existing decoded result.
            if digest not in self.worker.photos:
                count = getattr(self, "native_thumbnail_count", 0)
                amount = getattr(self, "native_thumbnail_bytes", 0)
                if count >= MAX_NATIVE_THUMBNAILS or len(content) > MAX_NATIVE_THUMBNAIL_BYTES - amount:
                    if not getattr(self, "native_thumbnail_limited", False):
                        self.remark("TELEGRAM_THUMBNAIL_LIMIT", original)
                        self.native_thumbnail_limited = True
                    break
                self.native_thumbnail_count = count + 1
                self.native_thumbnail_bytes = amount + len(content)
            self.worker.photo(content, self.worker.source_label or str(original), embedded=True,
                record=record + f"/photo.sizes[{index}]", blob_offset=size["blob_offset"])
            saved = self.worker.photos.get(digest)
            if saved and saved["status"] == "decoded":
                for origin in saved["sources"]:
                    if origin["source_record"] == record + f"/photo.sizes[{index}]" and origin["snapshot_id"] == self.worker.snapshot:
                        origin.update(history_fields)
                if (saved["width"], saved["height"]) != (size["width"], size["height"]):
                    self.remark("TELEGRAM_THUMBNAIL_DIMENSIONS_MISMATCH", original, record=record, size_index=index)
                    continue
                path = saved["path"]
                if path not in attachments:
                    attachments.append(path)
                self.worker.attachment_map[digest] = path
                metadata = self.worker.attachments.setdefault(digest, {"sha256": digest, "path": path,
                    "size": len(content), "kind": "cached_thumbnail", "sources": []})
                origin = {"source_file": self.worker.source_label or str(original),
                    "source_record": record + f"/photo.sizes[{index}]", "snapshot_id": self.worker.snapshot,
                    "source_sha256": self.worker.current_origin.get("Sha256"),
                    "blob_offset": size["blob_offset"], "offset_kind": "sqlite_tl_blob_relative", **history_fields}
                if origin not in metadata["sources"]:
                    metadata["sources"].append(origin)
            else:
                self.remark("TELEGRAM_CACHED_THUMBNAIL_UNREADABLE", original, record=record, size_index=index)
        return {"media_kind": "photo", "media_id": str(photo["id"]) if photo.get("id") is not None else None,
                "thumbnail_count": len(attachments),
                "media_status": "cached_thumbnail_available" if attachments else "photo_reference_only"}, attachments

    def sqlite_pair(self, copied, original):
        """Stage prior snapshots before SQLite may replay/remove working WAL."""
        from sqlite_history import iter_committed_snapshots, HistoryError
        wal = Path(str(copied) + "-wal")
        self.confirmed_tl_bodies = set()
        self.pending_deleted_records = []
        histories, report = [], {}
        residuals, residual_report = [], {}
        if wal.is_file() and wal.stat().st_size:
            if getattr(self, "recover_deleted", True):
                from sqlite_deleted import wal_fragments, DeletedError
                try:
                    residuals = wal_fragments(wal, cancel=lambda: self.stop, report=residual_report)
                except DeletedError as error:
                    self.remark("TELEGRAM_WAL_RESIDUALS_UNAVAILABLE", original, reason=error.code)
            try:
                histories = list(iter_committed_snapshots(copied, wal, self.worker.work,
                    report=report, cancel=lambda: self.stop, base_policy="wal_only"))
            except HistoryError as error:
                self.remark("TELEGRAM_WAL_HISTORY_UNAVAILABLE", original, reason=error.code)
                # No results survive a failed final source consistency check.
                histories = []
            if report.get("status") in ("complete", "complete_valid_prefix"):
                self.worker.remark("TELEGRAM_WAL_HISTORY_CHECKED", original, **report)
                if report.get("skipped") or report.get("tail_reason"):
                    self.remark("TELEGRAM_WAL_HISTORY_INCOMPLETE", original)
        self.deleted_current_verified = self.validate_wal(copied, original)
        self.current_wal = report if wal.is_file() and report.get("status") == "complete" else None
        original_snapshot = self.worker.snapshot
        try:
            result = self.sqlite(copied, original)
            self.current_wal = None
            native = self.last_native_database
            for history in reversed(histories):
                if self.stop:
                    break
                self.history_snapshot = history
                self.worker.snapshot = history["snapshot_id"]
                try:
                    self.sqlite(Path(history["path"]), original)
                except (sqlite3.DatabaseError, AutoError):
                    self.remark("TELEGRAM_WAL_HISTORY_PARSE_FAILED", original, commit_frame=history["commit_frame"])
            self.worker.snapshot = original_snapshot
            self.history_snapshot = None
            if native:
                self.publish_deleted_records(self.pending_deleted_records, original)
            if residuals and native:
                saved_origin, saved_label = self.worker.current_origin, self.worker.source_label
                self.worker.current_origin = self.worker.origins.get(str(wal.resolve()), saved_origin)
                self.worker.source_label = str(original) + "-wal"
                self.worker.snapshot = residual_report["wal_sha256"]
                try:
                    for item in residuals:
                        if self.stop:
                            break
                        if item.get("native_tl_body_sha256") in self.confirmed_tl_bodies:
                            continue
                        self.residual_fragment(item, Path(str(original) + "-wal"), record_kind="sqlite_wal_residual")
                    self.worker.remark("TELEGRAM_WAL_RESIDUALS_CHECKED", original, **residual_report)
                finally:
                    self.worker.current_origin, self.worker.source_label = saved_origin, saved_label
                    self.worker.snapshot = original_snapshot
            self.last_native_database = native
            return result
        finally:
            self.history_snapshot = None
            self.current_wal = None
            self.worker.snapshot = original_snapshot

    def validate_wal(self, copied, original):
        """Validate the committed WAL prefix before SQLite may replay it.

        Reject the entire sidecar on invalid framing/checksum/salt. This avoids
        silently claiming records from an unverified or partial tail.
        """
        wal = Path(str(copied) + "-wal")
        if not wal.exists() or wal.stat().st_size == 0:
            return True
        # WALs may be gigabytes long.  Keep only one SQLite page in memory;
        # reading the entire working copy can exceed the helper memory limit.
        with wal.open("rb") as stream:
            length = os.fstat(stream.fileno()).st_size
            header = stream.read(32)
            valid = len(header) == 32 and length <= MAX_SOURCE
            if valid:
                magic, version, pagesize, sequence, salt1, salt2, a, b = struct.unpack(">8I", header)
                valid = magic in (0x377f0682, 0x377f0683) and version == 3007000 and 512 <= pagesize <= 65536 and pagesize & (pagesize - 1) == 0
            if valid:
                order = "<" if magic == 0x377f0682 else ">"
                def check(block, a=0, b=0):
                    for first, second in struct.iter_unpack(order + "II", block):
                        a = (a + first + b) & 0xffffffff
                        b = (b + second + a) & 0xffffffff
                    return a, b
                valid = check(header[:24]) == (a, b) and (length - 32) % (24 + pagesize) == 0
                with copied.open("rb") as source:
                    head = source.read(100)
                valid = valid and len(head) >= 100 and int.from_bytes(head[16:18], "big") == (1 if pagesize == 65536 else pagesize)
                if valid:
                    for offset in range(32, length, 24 + pagesize):
                        frame, data = stream.read(24), stream.read(pagesize)
                        if len(frame) != 24 or len(data) != pagesize:
                            valid = False
                            break
                        page, size, s1, s2, ca, cb = struct.unpack(">6I", frame)
                        a, b = check(frame[:8] + data, a, b)
                        if not page or page > MAX_SOURCE // pagesize or size > MAX_SOURCE // pagesize or (s1, s2) != (salt1, salt2) or (a, b) != (ca, cb):
                            valid = False
                            break
                valid = valid and os.fstat(stream.fileno()).st_size == length
        if not valid:
            wal.unlink(missing_ok=True)
            Path(str(copied) + "-shm").unlink(missing_ok=True)
            self.remark("TELEGRAM_WAL_INVALID", original)
        else:
            self.worker.remark("WAL_CHECKED_COMMITS", original)
        return valid

    def heap_from(self, copied, original):
        from android_heap import recover, HeapError
        from memory_fragments import MAX_FRAGMENTS
        if self.stop:
            return []
        available = min(MAX_FRAGMENTS - self.fragments, MAX_MESSAGES - len(self.worker.messages))
        if available <= 0:
            self.remark("MEMORY_FRAGMENT_LIMIT", original)
            return []
        try:
            report = recover(copied, self.worker.work / "heap-index",
                matcher=self.fragment_matcher.matches if self.fragment_matcher else None,
                cancel=lambda: self.stop, limit=available,
                progress=lambda done, total: self.emit("progress", phase="telegram_heap", bytes=done, total=total))
        except HeapError as error:
            self.remark(str(error), original)
            return []
        ranges = []
        for value in report["records"]:
            if self.stop:
                break
            text = value.pop("text")
            ranges.append((value["byte_offset"], value["byte_offset"] + value["byte_length"]))
            self.worker.message("Telegram", text, "fragment", **value,
                record_kind="android_heap_message", completeness="structured_heap_candidate",
                application_confirmed=False, recovery_status="unattributed_structured_fragment",
                deleted=None, chat_id=None, sender_id=None, message_id=None, timestamp=None)
            self.fragments += 1
        self.remark("HPROF_GRAPH_NOT_CONFIRMED_DELETED_HISTORY", original)
        return ranges

    def fragments_from(self, copied, original, excluded_ranges=()):
        from memory_fragments import scan, scan_tl, MAX_FRAGMENTS
        if self.stop:
            return
        if self.fragments >= MAX_FRAGMENTS:
            self.remark("MEMORY_FRAGMENT_LIMIT", original)
            return
        from bisect import bisect_right
        typed_ranges = list(excluded_ranges)
        typed = scan_tl(copied, self.fragment_matcher,
                lambda done: self.emit("progress", phase="telegram_dump", bytes=done, fragments=self.fragments),
                limit=MAX_FRAGMENTS - self.fragments, cancel=lambda: self.stop)
        if not getattr(self, "recover_deleted", True):
            typed = ()
        for value in typed:
            typed_ranges.append((value["byte_offset"], value["byte_offset"] + value["byte_length"]))
            self.residual_fragment(value, original, record_kind="typed_tl_fragment")
        if self.fragments >= MAX_FRAGMENTS:
            self.remark("MEMORY_FRAGMENT_LIMIT", original)
            return
        merged = []
        for left, right in sorted(typed_ranges):
            if merged and left <= merged[-1][1]:
                merged[-1][1] = max(right, merged[-1][1])
            else:
                merged.append([left, right])
        typed_ranges = merged
        typed_starts = [left for left, right in typed_ranges]
        for value in scan(copied, self.fragment_matcher,
                          lambda done: self.emit("progress", phase="telegram_dump", bytes=done, fragments=self.fragments),
                          limit=MAX_FRAGMENTS - self.fragments, cancel=lambda: self.stop):
            range_index = bisect_right(typed_starts, value["byte_offset"]) - 1
            if range_index >= 0 and value["byte_offset"] + value["byte_length"] <= typed_ranges[range_index][1]:
                continue
            text = value.pop("text")
            self.worker.message("Telegram", text, "fragment", **value,
                record_kind="memory_fragment", completeness="unattributed_text",
                application_confirmed=False,
                source_record=f"file-byte:{value['byte_offset']}:{value['encoding']}")
            self.fragments += 1
        self.remark("UNATTRIBUTED_TEXT_NOT_CHAT_HISTORY", original)
        if self.fragments >= MAX_FRAGMENTS:
            self.remark("MEMORY_FRAGMENT_LIMIT", original)

    def candidate(self, source, kind):
        lower = source.name.casefold()
        stem = lower.split(".", 1)[0]
        # Telegram Desktop account/session blobs use hex identifiers. We do
        # not open them even when a misleading extension has been appended.
        standalone_wal = self.scan_fragments and lower.endswith("-wal") and (kind == "dump" or not Path(str(source)[:-4]).is_file())
        if stem in NATIVE_PRIVATE or lower.endswith(("-shm", ".partial")) or lower.endswith("-wal") and not standalone_wal:
            return
        if re.fullmatch(r"[0-9a-f]{16}[s01]?", stem):
            self.counts["encrypted_sources"] += 1
            self.remark("ENCRYPTED_CACHE_UNSUPPORTED", source)
            return
        if lower == "chat-index.sqlite" and (source.parent / "messages.jsonl").is_file():
            return
        self.files += 1
        if self.files > MAX_FILES:
            self.stop = True
            self.remark("TELEGRAM_SCAN_LIMIT", source.parent)
            return
        before_messages = len(self.worker.messages)
        before_images = len(self.worker.photos)
        try:
            size = source.stat().st_size
            if not size:
                return
            if size > MAX_SOURCE:
                self.remark("TELEGRAM_SOURCE_LIMIT", source)
                return
            with source.open("rb") as f:
                head = f.read(4096)
            if head.startswith(b"TDF$"):
                self.counts["encrypted_sources"] += 1
                self.remark("ENCRYPTED_CACHE_UNSUPPORTED", source, size=size)
                return
            sqlite = head.startswith(b"SQLite format 3\x00")
            heap = head.startswith(b"JAVA PROFILE ")
            dump = self.scan_fragments and (kind == "dump" or standalone_wal or lower.endswith((".dmp", ".dump", ".mem", ".hprof", ".raw", ".bin")))
            jsonl = lower == "messages.jsonl"
            markup = lower.endswith((".html", ".htm")) or b'<div class="message' in head
            json_candidate = lower.endswith(".json") or head.lstrip().startswith(b"{")
            image = head.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"BM", b"II*\x00", b"MM\x00*")) or head[:4] == b"RIFF" and head[8:12] == b"WEBP" or head[4:8] == b"ftyp"
            # Plain media containers within Telegram's own file cache are also
            # inspected for embedded images. Unknown app/account blobs aren't.
            container = kind in {"telegram_files", "desktop_cache"} and (lower.endswith((".cache", ".bin", ".dat")) or not source.suffix) and (b"\xff\xd8\xff" in head or b"\x89PNG\r\n\x1a\n" in head or b"RIFF" in head)
            if not any((sqlite, heap, jsonl, markup, json_candidate, image, container, dump)):
                return
            token = hashlib.sha256(str(source).encode()).hexdigest()[:24]
            copied = self.copy(source, self.worker.work / "input" / token / source.name)
            self.worker.current_origin = self.worker.origins[str(copied.resolve())]
            self.worker.snapshot = self.worker.current_origin["Sha256"]
            self.worker.source_label = str(source)
            self.counts["readable_sources"] += 1
            self.worker.sources.append({"source": str(source), "sha256": self.worker.snapshot, "size": size,
                                        "status": "copied_input", "source_id": self.worker.current_origin["Id"]})
            if sqlite:
                # Published JSONL already contains the same canonical archive,
                # choose it once to avoid importing duplicate unknown-ID HTML.
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(str(source) + suffix)
                    if sidecar.is_file():
                        self.copy(sidecar, Path(str(copied) + suffix))
                for suffix in ("", "-wal", "-shm"):
                    original_member = Path(str(source) + suffix)
                    verified_copy = self.copied.get(str(original_member).casefold())
                    if verified_copy and _hash(original_member) != self.worker.origins[str(verified_copy.resolve())]["Sha256"]:
                        raise AutoError("TELEGRAM_SOURCE_CHANGED")
                self.last_native_database = False
                try:
                    self.sqlite_pair(copied, source)
                except (sqlite3.DatabaseError, AutoError):
                    if not self.scan_fragments or not re.fullmatch(r"cache\d*\.db", lower):
                        raise
                    self.last_native_database = True
                    self.remark("TELEGRAM_SQLITE_INVALID_FRAGMENTS_ONLY", source)
                if self.scan_fragments and self.last_native_database:
                    self.fragments_from(copied, source)
                    wal = Path(str(copied) + "-wal")
                    if wal.is_file():
                        self.worker.current_origin = self.worker.origins[str(wal.resolve())]
                        self.worker.source_label = str(source) + "-wal"
                        self.worker.snapshot = self.worker.current_origin["Sha256"]
                        self.fragments_from(wal, Path(str(source) + "-wal"))
            elif heap:
                ranges = self.heap_from(copied, source)
                if self.scan_fragments:
                    self.fragments_from(copied, source, ranges)
            elif dump and not (jsonl or json_candidate or markup or image):
                self.fragments_from(copied, source)
            elif jsonl:
                if (source.parent / "job.incomplete").exists():
                    self.remark("TELEGRAM_ARCHIVE_INCOMPLETE", source)
                    return
                self.canonical_records(copied, source)
            elif json_candidate and size <= MAX_TEXT:
                try:
                    data = json.loads(copied.read_text(encoding="utf-8-sig"))
                except (ValueError, UnicodeError):
                    data = None
                if _export_json(data):
                    self.references(_references(data), source.parent, copied.parent)
                    self.worker.telegram_json(copied)
            elif markup and size <= MAX_TEXT:
                # Parse solely as data. No browser, HTML source execution or
                # remote resource retrieval participates in this pipeline.
                from engine import TelegramHTML
                parser = TelegramHTML()
                parser.feed(copied.read_text(encoding="utf-8-sig", errors="replace"))
                if parser.messages:
                    self.references((r for m in parser.messages for r in m["attachment_refs"]), source.parent, copied.parent)
                    self.worker.telegram_html(copied)
            if image or container:
                self.worker.scan_images(copied)
            if len(self.worker.messages) > MAX_MESSAGES:
                self.worker.messages = self.worker.messages[:MAX_MESSAGES]
                self.stop = True
                self.remark("TELEGRAM_MESSAGE_LIMIT", source)
            if len(self.worker.messages) != before_messages or len(self.worker.photos) != before_images:
                self.emit("progress", phase="telegram_read", files=self.files, messages=len(self.worker.messages), photos=len(self.worker.photos))
        except Exception as error:
            from text_match import MatchError
            if isinstance(error, MatchError):
                raise AutoError(error.code) from None
            self.counts["blocked_sources"] += 1
            self.remark(error.code if isinstance(error, AutoError) else "TELEGRAM_SOURCE_UNAVAILABLE", source)

    def run(self):
        roots = _roots(self.request)
        self.output.mkdir(parents=True, exist_ok=True)
        self.scratch.mkdir(parents=True, exist_ok=True)
        for name in ("media", "previews"):
            (self.output / name).mkdir(exist_ok=True)
        (self.output / "job.incomplete").write_text("Telegram analysis did not finish.\n", encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="telegram-analysis-", dir=self.scratch) as work:
            self.worker = self.importer_type(self.output, self.output, secrets={}, deep=True)
            self.worker.work = Path(work)
            self.worker.telegram_only = True
            try:
                from PIL import Image
                Image.MAX_IMAGE_PIXELS = 60_000_000
                import pillow_heif
                pillow_heif.register_heif_opener()
            except ImportError:
                self.remark("HEIF_RUNTIME_UNAVAILABLE")
            seen_roots = set()
            for value, kind in roots:
                try:
                    root = _plain_path(value)
                    if not root.exists():
                        continue
                    if _within(root, self.output) or _within(root, self.scratch):
                        continue
                    identity = str(root).casefold()
                    if identity in seen_roots:
                        continue
                    seen_roots.add(identity)
                    self.counts["discovered_sources"] += 1
                    self.emit("progress", phase="telegram_discovery", sources=self.counts["discovered_sources"])
                    if kind == "desktop_cache":
                        self.counts["encrypted_sources"] += 1
                        self.remark("DESKTOP_CACHE_NOT_CHAT_EXPORT", root)
                        self.remark("ENCRYPTED_CACHE_UNSUPPORTED", root)
                    for source in self.walk(root):
                        identity = str(source).casefold()
                        if identity in self.seen:
                            continue
                        self.seen.add(identity)
                        self.candidate(source, kind)
                        if self.stop:
                            break
                except (OSError, AutoError) as error:
                    if isinstance(error, AutoError) and error.code in {"REGEX_INVALID", "REGEX_TIMEOUT"}:
                        raise
                    self.counts["blocked_sources"] += 1
                    self.remark(error.code if isinstance(error, AutoError) else "TELEGRAM_ROOT_UNAVAILABLE", value)
                if self.stop:
                    break
            self.worker.messages.sort(key=lambda m: (_timestamp(m.get("timestamp")) is None, -(_timestamp(m.get("timestamp")) or 0)))
            # Distinguish available exports from saved notification previews.
            history = [m for m in self.worker.messages if m.get("record_kind") != "notification" and m.get("evidence_kind") != "fragment"]
            self.notifications = sum(m.get("record_kind") == "notification" for m in self.worker.messages)
            self.fragments = sum(m.get("evidence_kind") == "fragment" for m in self.worker.messages)
            if not history:
                self.remark("NO_READABLE_TELEGRAM_HISTORY")
            self.worker.publish()
            (self.output / "acquisition.json").write_text(json.dumps({"protocol": 1, "kind": "telegram_automatic", "Files": self.copy_records}, ensure_ascii=False, indent=2), encoding="utf-8")
            dated = [m for m in history if _timestamp(m.get("timestamp")) is not None]
            latest = dated[0]["timestamp"] if dated else None
            notes = [x.get("code") for x in self.worker.sources if "code" in x]
            self.warnings = list(dict.fromkeys([*self.warnings, *notes]))
            summary = {"status": "partial" if self.warnings else "complete", "code": "PARTIAL_DATA" if history and self.warnings else "OK" if history else "NO_READABLE_TELEGRAM_HISTORY",
                       "messages": len(self.worker.messages), "history_messages": len(history), "notification_records": self.notifications, "fragment_records": self.fragments,
                       "native_records": sum(m.get("record_kind") in ("tl_message", "sqlite_deleted_record") for m in self.worker.messages),
                       "previous_records": sum(m.get("evidence_kind") == "previous" for m in self.worker.messages),
                       "deleted_supported_records": sum(m.get("recovery_status") == "deleted_supported_by_evidence" for m in self.worker.messages),
                       "structured_fragment_records": sum(m.get("record_kind") in ("sqlite_residual_fragment", "sqlite_wal_residual", "typed_tl_fragment", "android_heap_message") for m in self.worker.messages),
                       "photos": sum(p["status"] == "decoded" for p in self.worker.photos.values()),
                       "media": sum(1 for p in (self.output / "media").iterdir() if p.is_file()),
                       "latest_timestamp": latest, "warnings": self.warnings, **self.counts,
                       "destination": str(self.output), "archive": str(self.output),
                       "chat_archive": str(self.output / "Переписки.html"), "photo_archive": str(self.output / "Фотографии.html"),
                       "sources": str(self.output / "sources.json")}
            (self.output / "telegram-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        (self.output / "job.incomplete").unlink()
        try:
            self.scratch.rmdir()
        except OSError:
            pass
        return summary


def analyze(request, importer, emit):
    if request.get("protocol") != 1 or request.get("operation") != "telegram_analyze" or not isinstance(request.get("options", {}), dict):
        raise AutoError("PROTOCOL_UNSUPPORTED")
    return Analyzer(request, importer, emit).run()


def import_database(worker, source):
    """Reuse the exact Telegram parser in an explicitly chosen phone snapshot.

    No WhatsApp/Signal fallback is used. This entry operates on another local
    DB/WAL/SHM working copy, so SQLite never changes acquisition snapshots.
    """
    analyzer = Analyzer.__new__(Analyzer)
    analyzer.worker = worker
    analyzer.emit = lambda *a, **k: None
    analyzer.stop = False
    analyzer.notifications = 0
    analyzer.notification_identities = {}
    analyzer.history_snapshot = None
    analyzer.current_wal = None
    analyzer.recover_deleted = True
    analyzer.deleted_current_verified = True
    analyzer.scan_fragments = False
    analyzer.fragments = 0
    analyzer.fragment_matcher = None
    analyzer.warnings = []
    analyzer.copied = {}
    analyzer.bytes = 0
    analyzer.copy_records = []
    analyzer.counts = dict(discovered_sources=0, readable_sources=0, encrypted_sources=0, blocked_sources=0)
    source = Path(source)
    target = worker.work / "telegram-sqlite" / hashlib.sha256(str(source).encode()).hexdigest()[:24] / source.name
    analyzer.copy(source, target)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(source) + suffix)
        if sidecar.is_file():
            analyzer.copy(sidecar, Path(str(target) + suffix))
    return analyzer.sqlite_pair(target, source)
