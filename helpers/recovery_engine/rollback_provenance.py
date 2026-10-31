"""Bounded archive display metadata for SQLite rollback before-images.

Structural checks here never open original sources or authenticate content.
Sparse SQLite checksums cannot establish hot/committed/deleted state.
"""
import re

ROLLBACK_FIELDS = (
    "rollback_journal_sha256", "rollback_snapshot_sha256", "rollback_proof",
    "rollback_initial_pages", "rollback_page_map", "rollback_page_map_sha256",
    "rollback_hot_state", "rollback_current_state_confirmed", "rollback_checksum_kind",
    "rollback_content_authenticity_verified", "rollback_parse_status", "rollback_tail_reason",
    "rollback_validated_prefix_bytes", "rollback_header_offset", "rollback_record_offset",
    "rollback_page", "rollback_payload_length", "rollback_payload_sha256",
    "rollback_payload_ranges", "rollback_payload_chain_verified",
)
_HASH = re.compile(r"[a-f0-9]{64}\Z")


def _hash(value):
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def normalized(raw):
    if not any(raw.get(name) is not None for name in ROLLBACK_FIELDS):
        return {}
    result = {name: raw[name] for name in ROLLBACK_FIELDS if raw.get(name) is not None}
    digest = result.get("rollback_journal_sha256")
    if (not _hash(digest) or result.get("rollback_hot_state") != "unknown" or
            result.get("rollback_current_state_confirmed") is not False or
            result.get("rollback_content_authenticity_verified") is not False or
            result.get("rollback_checksum_kind") != "sqlite_sparse_32bit" or
            result.get("rollback_parse_status") not in ("complete", "validated_prefix") or
            type(result.get("rollback_initial_pages")) is not int or not 1 <= result["rollback_initial_pages"] <= 131072):
        return None
    if (result.get("rollback_page_map") != "provenance/rollback/" + digest + ".json" or
            not _hash(result.get("rollback_page_map_sha256"))):
        return None
    proof = result.get("rollback_proof")
    if proof in ("all_pages_from_validated_rollback_journal", "archive_text_from_rollback_snapshot"):
        if not _hash(result.get("rollback_snapshot_sha256")) or result["rollback_parse_status"] != "complete" or result.get("rollback_tail_reason") is not None:
            return None
    elif proof in ("validated_rollback_page_fragment", "validated_rollback_payload_chain"):
        if result.get("rollback_snapshot_sha256") is not None:
            return None
    else:
        return None
    for name in ("rollback_validated_prefix_bytes", "rollback_header_offset", "rollback_record_offset"):
        if name in result and (type(result[name]) is not int or not 0 <= result[name] <= 256 * 1024 * 1024):
            return None
    if "rollback_page" in result and (type(result["rollback_page"]) is not int or not 1 <= result["rollback_page"] <= result["rollback_initial_pages"]):
        return None
    reason = result.get("rollback_tail_reason")
    if reason is not None and (not isinstance(reason, str) or not re.fullmatch(r"[a-z_]{1,64}", reason)):
        return None
    payload_fields = ("rollback_payload_length", "rollback_payload_sha256", "rollback_payload_ranges", "rollback_payload_chain_verified")
    if proof == "archive_text_from_rollback_snapshot" and any(name in result for name in payload_fields):
        return None
    if any(name in result for name in payload_fields):
        length = result.get("rollback_payload_length")
        ranges = result.get("rollback_payload_ranges")
        if (type(length) is not int or not 1 <= length <= 4 * 1024 * 1024 or
                not _hash(result.get("rollback_payload_sha256")) or
                result.get("rollback_payload_chain_verified") is not True or
                not isinstance(ranges, list) or not 2 <= len(ranges) <= 4096):
            return None
        keys = {"logical_offset", "bytes", "sqlite_page", "physical_source", "physical_byte_offset"}
        position, pages, physical, cleaned = 0, set(), [], []
        for value in ranges:
            if not isinstance(value, dict) or set(value) != keys:
                return None
            logical, amount, page, source, offset = (value[key] for key in
                ("logical_offset", "bytes", "sqlite_page", "physical_source", "physical_byte_offset"))
            if (type(logical) is not int or logical != position or type(amount) is not int or not 1 <= amount <= 65536 or
                    type(page) is not int or not 1 <= page <= result["rollback_initial_pages"] or page in pages or
                    source != "rollback_journal" or type(offset) is not int or not 0 <= offset <= 256 * 1024 * 1024 - amount):
                return None
            position += amount
            if position > length:
                return None
            pages.add(page)
            physical.append((offset, offset + amount))
            cleaned.append(dict(value))
        physical.sort()
        if position != length or any(left[1] > right[0] for left, right in zip(physical, physical[1:])):
            return None
        result["rollback_payload_ranges"] = cleaned
    if proof == "validated_rollback_payload_chain" and not result.get("rollback_payload_chain_verified"):
        return None
    return result
