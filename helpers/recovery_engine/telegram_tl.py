"""Bounded, strict subset decoder for readable Telegram Android message blobs.

Protocol facts were checked against official Telegram Android sources pinned at
4de548e79fed27f1a66fbdff84223321838fe925 (layer 232):
https://github.com/DrKLO/Telegram/blob/4de548e79fed27f1a66fbdff84223321838fe925/TMessagesProj/src/main/java/org/telegram/tgnet/TLRPC.java
https://github.com/DrKLO/Telegram/blob/4de548e79fed27f1a66fbdff84223321838fe925/TMessagesProj/src/main/java/org/telegram/tgnet/tl/legacy/TL_legacy_message.java

This is an independent reader of the public wire format, not Android code.
It does not decrypt tdata, access accounts, infer missing identities, execute
entities/URLs or follow Android's local attachment path. Unknown fields fail
closed. A successfully decoded record is a surviving record, not proof that
it was deleted or that attachments survived. Caller must validate DB row keys
and report snapshot/original-byte provenance independently.
"""
from __future__ import annotations

import struct

SOURCE_COMMIT = "4de548e79fed27f1a66fbdff84223321838fe925"
MAX_BLOB = 4 * 1024 * 1024
MAX_STRING = 1024 * 1024
MAX_VECTOR = 4096
MAX_PHOTO_SIZES = 64
MAX_PHOTO_DIMENSION = 32768
VECTOR = 0x1CB5C415


class TelegramTlError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


# Constructor: layer, flags2 present, boolean flags, boolean flags2,
# declared payload flags, declared payload flags2. Flags with unsupported
# nested objects are rejected, never blindly skipped. These are exact facts
# from the corresponding pinned class, not guessed by layer-number ranges.
PROFILES = {
    0x7600B9D3: (232, True, 0xD2C6032, 0x312, 0x72D38FCC, 0x83CED),
    0x95EF6F2B: (226, True, 0xD2C6032, 0x312, 0x72D38FCC, 0x81CED),
    0x3AE56482: (224, True, 0xD2C6032, 0x312, 0x72D38FCC, 0x1CED),
    0x9CB490E9: (222, True, 0xD2C6032, 0x312, 0x72D38FCC, 0xCED),
    0xB92F76CF: (220, True, 0xD2C6032, 0x312, 0x72D38FCC, 0x4ED),
    0x9815CEC8: (216, True, 0xD2C6032, 0x312, 0x72D38FCC, 0xED),
    0xEABCDD4D: (205, True, 0xD2C6032, 0x12, 0x72D38FCC, 0x6D),
    0x96FDBBE9: (199, True, 0xD2C6032, 0x12, 0x72D38FCC, 0x2D),
    0x94345242: (195, True, 0xD2C6032, 0x12, 0x72D38FCC, 0xD),
    0xBDE09C2E: (180, True, 0xD2C6032, 0x2, 0x72D38FCC, 0x5),
    0x2357BF25: (179, True, 0xD2C6032, 0x2, 0x72D38FCC, 0x1),
    0xA66C7EFC: (176, False, 0xD2C6032, 0, 0x72D38FCC, 0),
    0x1E4C8A69: (175, False, 0xD2C6032, 0, 0x32D38FCC, 0),
    0x76BEC211: (173, False, 0xD2C6032, 0, 0x12D38FCC, 0),
    0x38116EE0: (169, False, 0xD2C6032, 0, 0x2D38FCC, 0),
    0x85D6CBE2: (135, False, 0x52C6032, 0, 0x2C38FCC, 0),
    0xBCE383D2: (131, False, 0x12C6032, 0, 0x2C38FCC, 0),
    0x58AE39C9: (123, False, 0x12C6032, 0, 0xC38FCC, 0),
    0xF52E6B7F: (118, False, 0x2C6032, 0, 0x438FCC, 0),
}
PEERS = {
    0x59511722: ("user", 8), 0x36C6019A: ("chat", 8),
    0xA2A5371E: ("channel", 8), 0x9DB1BC6D: ("user", 4),
    0xBAD0E5BB: ("chat", 4), 0xBDDDE532: ("channel", 4),
}
SIMPLE_ENTITIES = {
    0xBB92BA95: "unknown", 0xFA04579D: "mention", 0x6F635B0D: "hashtag",
    0x6CEF8AC7: "bot_command", 0x6ED02538: "url", 0x64E475C2: "email",
    0xBD610BC9: "bold", 0x826F8B60: "italic", 0x28A20571: "code",
    0x9C4E7E8B: "underline", 0xBF0693D4: "strike", 0x4C4E743F: "cashtag",
    0x761E6AF4: "bank_card", 0x9B69E34B: "phone", 0x32CA960F: "spoiler",
    0x020DF5D0: "blockquote",
}


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.at = memoryview(data), 0
        self.elements = 0

    def take(self, count: int) -> memoryview:
        if count < 0 or count > len(self.data) - self.at:
            raise TelegramTlError("TL_TRUNCATED")
        begin = self.at
        self.at += count
        return self.data[begin:self.at]

    def i32(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.take(8))[0]

    def data_string_span(self) -> tuple[bytes, int]:
        first = self.take(1)[0]
        if first == 255:
            raise TelegramTlError("TL_INVALID_STRING_LENGTH")
        header = 1
        if first == 254:
            raw = self.take(3)
            length = raw[0] | raw[1] << 8 | raw[2] << 16
            header = 4
            if length < 254:
                raise TelegramTlError("TL_NONCANONICAL_STRING")
        else:
            length = first
        if length > MAX_STRING:
            raise TelegramTlError("TL_STRING_LIMIT")
        offset = self.at
        value = bytes(self.take(length))
        if any(self.take(-(length + header) % 4)):
            raise TelegramTlError("TL_INVALID_PADDING")
        return value, offset

    def data_string(self) -> bytes:
        return self.data_string_span()[0]

    def string(self) -> str:
        try:
            return self.data_string().decode("utf-8", "strict")
        except UnicodeError as error:
            raise TelegramTlError("TL_INVALID_UTF8") from error

    def vector(self, parser, limit=MAX_VECTOR):
        if self.u32() != VECTOR:
            raise TelegramTlError("TL_INVALID_VECTOR")
        count = self.i32()
        if count < 0 or count > min(limit, MAX_VECTOR) or self.elements + count > MAX_VECTOR:
            raise TelegramTlError("TL_VECTOR_LIMIT")
        self.elements += count
        return [parser() for _ in range(count)]


def _flags(value: int, allowed: int):
    if value & ~allowed:
        raise TelegramTlError("TL_UNSUPPORTED_FLAGS")


def _nonnegative(value: int) -> int:
    if value < 0:
        raise TelegramTlError("TL_INVALID_NUMBER")
    return value


def _peer(reader: _Reader, allow_zero=False):
    spec = PEERS.get(reader.u32())
    if spec is None:
        raise TelegramTlError("TL_UNSUPPORTED_PEER")
    kind, width = spec
    value = reader.i64() if width == 8 else reader.i32()
    if value < 0 or value == 0 and not allow_zero:
        raise TelegramTlError("TL_INVALID_PEER")
    return {"kind": kind, "id": value} if value else None


def _entities(reader: _Reader, text: str):
    units = len(text.encode("utf-16-le")) // 2

    def entity():
        constructor = reader.u32()
        kind = SIMPLE_ENTITIES.get(constructor)
        if constructor == 0xF1CCAAAC:
            _flags(reader.u32(), 1)
            kind = "blockquote"
        special = {
            0x73924BE0: "pre", 0x76A6D327: "text_url", 0x352DCA58: "mention_name",
            0xDC7B1140: "mention_name", 0xC8CF05F8: "custom_emoji",
        }
        if kind is None:
            kind = special.get(constructor)
        if kind is None:
            raise TelegramTlError("TL_UNSUPPORTED_ENTITY")
        offset, length = reader.i32(), reader.i32()
        if offset < 0 or length <= 0 or offset > units - length:
            raise TelegramTlError("TL_INVALID_ENTITY_RANGE")
        result = {"type": kind, "offset": offset, "length": length}
        if constructor in (0x73924BE0, 0x76A6D327):
            # Display-only metadata; URLs never fetched or executed.
            result["language" if constructor == 0x73924BE0 else "url"] = reader.string()
        elif constructor == 0x352DCA58:
            result["user_id"] = _nonnegative(reader.i32())
        elif constructor in (0xDC7B1140, 0xC8CF05F8):
            result["user_id" if constructor == 0xDC7B1140 else "document_id"] = _nonnegative(reader.i64())
        return result

    return reader.vector(entity)


def _photo_location(reader: _Reader):
    """Consume legacy location fields; never publish secrets or follow paths."""
    constructor = reader.u32()
    if constructor == 0xBC7FC6CD:
        reader.i64()
        reader.i32()
    elif constructor == 0x7C596B46:
        reader.i64()
        reader.i32()
        reader.i64()
    elif constructor in (0x53D69076, 0x091D11EB):
        reader.i32()
        reader.i64()
        reader.i32()
        reader.i64()
        if constructor == 0x091D11EB:
            reader.data_string()
    else:
        raise TelegramTlError("TL_UNSUPPORTED_PHOTO_LOCATION")


def _photo_size(reader: _Reader):
    constructor = reader.u32()
    if constructor not in (0x0E17E23C, 0xE0B0BC2E, 0xD8214D41, 0x75C78E60,
                           0x77BFB61B, 0x021E1AD6, 0xE9A734FA, 0xFA3EFB95, 0x5AA86A51):
        raise TelegramTlError("TL_UNSUPPORTED_PHOTO_SIZE")
    kind = reader.string()
    if len(kind) > 32:
        raise TelegramTlError("TL_PHOTO_TYPE_LIMIT")
    result = {"type": kind, "constructor": f"0x{constructor:08x}"}
    if constructor == 0x0E17E23C:
        return {**result, "kind": "empty"}
    if constructor in (0xE0B0BC2E, 0xD8214D41):
        content = reader.data_string()
        # Stripped JPEG and compressed vector paths are not complete original
        # images. Validate framing and retain only bounded metadata here.
        return {**result, "kind": "stripped" if constructor == 0xE0B0BC2E else "path",
                "encoded_bytes": len(content)}
    if constructor in (0x77BFB61B, 0xE9A734FA, 0x5AA86A51):
        _photo_location(reader)
    width, height = reader.i32(), reader.i32()
    if not 0 < width <= MAX_PHOTO_DIMENSION or not 0 < height <= MAX_PHOTO_DIMENSION:
        raise TelegramTlError("TL_INVALID_PHOTO_DIMENSIONS")
    result.update(width=width, height=height)
    if constructor in (0x021E1AD6, 0xE9A734FA):
        content, offset = reader.data_string_span()
        result.update(kind="cached", content=content, blob_offset=offset)
    elif constructor in (0xFA3EFB95, 0x5AA86A51):
        sizes = reader.vector(lambda: _nonnegative(reader.i32()), MAX_PHOTO_SIZES)
        if any(a > b for a, b in zip(sizes, sizes[1:])):
            raise TelegramTlError("TL_INVALID_PHOTO_PROGRESSIVE")
        result.update(kind="progressive", encoded_bytes=sizes[-1] if sizes else 0)
    else:
        result.update(kind="remote", encoded_bytes=_nonnegative(reader.i32()))
    return result


def _photo(reader: _Reader):
    constructor = reader.u32()
    if constructor == 0x2331B22D:
        return {"type": "empty", "id": reader.i64(), "sizes": []}
    if constructor not in (0xFB197A65, 0xD07504A5, 0x9C477DD8, 0x9288DD29, 0xCDED42FE):
        raise TelegramTlError("TL_UNSUPPORTED_PHOTO")
    flags = reader.u32() if constructor != 0xCDED42FE else 0
    # Animated/photo video sizes require their own decoder. Reject them rather
    # than guessing the length of an unknown nested VideoSize.
    _flags(flags, 1)
    photo_id = reader.i64()
    reader.i64()  # access_hash: consume, never return it
    if constructor in (0xFB197A65, 0xD07504A5, 0x9C477DD8):
        reader.data_string()  # file_reference: consume, never publish it
    date = _nonnegative(reader.i32())
    sizes = reader.vector(lambda: _photo_size(reader), MAX_PHOTO_SIZES)
    if constructor in (0xFB197A65, 0xD07504A5):
        _nonnegative(reader.i32())  # dc_id; no network lookup
    return {"type": "photo", "id": photo_id, "date": date, "sizes": sizes,
            "constructor": f"0x{constructor:08x}"}


def _media(reader: _Reader):
    constructor = reader.u32()
    if constructor == 0x3DED6320:
        return {"type": "empty"}
    if constructor == 0x9F84F49E:
        return {"type": "unsupported", "attachment_available": False}
    if constructor in (0xE216EB63, 0x695150D7, 0xB5223B0F, 0x3D8CE53D, 0xC8C45A2A):
        result = {"type": "photo", "constructor": f"0x{constructor:08x}"}
        if constructor in (0x3D8CE53D, 0xC8C45A2A):
            result["photo"] = _photo(reader)
            if constructor == 0x3D8CE53D:
                result["legacy_caption"] = reader.string()
        else:
            flags = reader.u32()
            # Current live photos have nested Document payload; unsupported.
            _flags(flags, 7 if constructor == 0xB5223B0F else 13)
            result["photo"] = _photo(reader) if flags & 1 else {"type": "empty", "sizes": []}
            if constructor == 0xB5223B0F and flags & 2:
                result["legacy_caption"] = reader.string()
            if flags & 4:
                result["ttl_seconds"] = _nonnegative(reader.i32())
            result["spoiler"] = bool(flags & 8)
        return result
    raise TelegramTlError("TL_UNSUPPORTED_MEDIA")


def _markup(reader: _Reader):
    constructor = reader.u32()
    flags = reader.u32()
    if constructor == 0xA03E5B85:
        _flags(flags, 1 << 2)
    elif constructor == 0x86B40B08:
        _flags(flags, (1 << 1) | (1 << 2) | (1 << 3))
        if flags & (1 << 3):
            reader.string()
    else:
        raise TelegramTlError("TL_UNSUPPORTED_MARKUP")


def _forward(reader: _Reader):
    constructor, flags = reader.u32(), reader.u32()
    if constructor not in (0x4E4DF4BB, 0x5F777DCE, 0x353A686B):
        raise TelegramTlError("TL_UNSUPPORTED_FORWARD")
    allowed = 0xFFD if constructor == 0x4E4DF4BB else 0xFD if constructor == 0x5F777DCE else 0x7F
    _flags(flags, allowed)
    result = {}
    if flags & 1:
        result["from_peer"] = _peer(reader) if constructor != 0x353A686B else {"kind": "user", "id": _nonnegative(reader.i32())}
    if flags & 32:
        result["from_name"] = reader.string()
    result["date"] = _nonnegative(reader.i32())
    if constructor == 0x353A686B and flags & 2:
        result["from_peer"] = {"kind": "channel", "id": _nonnegative(reader.i32())}
    if flags & 4:
        result["channel_post"] = reader.i32()
    if flags & 8:
        result["post_author"] = reader.string()
    if flags & 16:
        result["saved_peer"] = _peer(reader)
        result["saved_message_id"] = reader.i32()
    if flags & 256:
        result["saved_from_peer"] = _peer(reader)
    if flags & 512:
        result["saved_from_name"] = reader.string()
    if flags & 1024:
        result["saved_date"] = _nonnegative(reader.i32())
    if flags & 64:
        result["psa_type"] = reader.string()
    return result


def _reply(reader: _Reader):
    constructor, flags = reader.u32(), reader.u32()
    masks = {
        0xA6D57763: 0xF, 0x3D5C1693: 0xFF, 0x6EEBCABD: 0x3FF,
        0xAFBC09DB: 0x7FF, 0x6917560B: 0xFFF, 0x1B97DD66: 0x3FFF,
        0xDDB5AB75: 0x3FFF,  # RichText bit14 explicitly unsupported.
    }
    if constructor not in masks:
        raise TelegramTlError("TL_UNSUPPORTED_REPLY")
    _flags(flags, masks[constructor])
    result = {}
    if constructor == 0xA6D57763 or flags & 16:
        result["message_id"] = reader.i32()
    if flags & 1:
        result["peer"] = _peer(reader)
    if flags & 32:
        result["forward"] = _forward(reader)
    if flags & 256:
        result["media"] = _media(reader)
    if flags & 2:
        result["top_id"] = reader.i32()
    if flags & 64:
        result["quote_text"] = reader.string()
    if flags & 128:
        if "quote_text" not in result:
            raise TelegramTlError("TL_QUOTE_WITHOUT_TEXT")
        result["quote_entities"] = _entities(reader, result["quote_text"])
    if flags & 1024:
        result["quote_offset"] = _nonnegative(reader.i32())
    if flags & 2048:
        result["todo_item_id"] = reader.i32()
    if flags & 4096:
        reader.data_string()
    return result


def _replies(reader: _Reader):
    constructor, flags = reader.u32(), reader.u32()
    if constructor not in (0x83D60FC2, 0x4128FAAC):
        raise TelegramTlError("TL_UNSUPPORTED_REPLIES")
    _flags(flags, 15)
    result = {"count": _nonnegative(reader.i32()), "pts": _nonnegative(reader.i32())}
    if flags & 2:
        reader.vector(lambda: _peer(reader))
    if flags & 1:
        result["channel_id"] = _nonnegative(reader.i64() if constructor == 0x83D60FC2 else reader.i32())
    if flags & 4:
        result["max_id"] = reader.i32()
    if flags & 8:
        result["read_max_id"] = reader.i32()
    return result


def _restrictions(reader: _Reader):
    def restriction():
        if reader.u32() != 0xD072ACB4:
            raise TelegramTlError("TL_UNSUPPORTED_RESTRICTION")
        return {"platform": reader.string(), "reason": reader.string(), "text": reader.string()}
    return reader.vector(restriction)


def parse_message(blob: bytes | bytearray | memoryview) -> dict:
    """Return one structurally checked supported message or raise a code.

    Only zero or one validated Android local-path string (and local forward
    id for a negative message id) may follow the TL message. That path is not
    returned, resolved, followed, or used as attachment evidence. No scanning
    for embedded strings takes place on an unsupported object.
    """
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TelegramTlError("TL_INVALID_INPUT")
    if not blob or len(blob) > MAX_BLOB:
        raise TelegramTlError("TL_BLOB_LIMIT")
    reader = _Reader(blob)
    constructor = reader.u32()
    profile = PROFILES.get(constructor)
    if profile is None:
        raise TelegramTlError("TL_UNSUPPORTED_CONSTRUCTOR")
    layer, second, bools, bools2, payload, payload2 = profile
    flags = reader.u32()
    flags2 = reader.u32() if second else 0
    _flags(flags, bools | payload)
    _flags(flags2, bools2 | payload2)
    # Complex reactions/fact-check/suggested-post/RichText need independent
    # typed decoders; accepting their mere presence would leave offsets unsafe.
    if flags & (1 << 20) or flags2 & ((1 << 3) | (1 << 7) | (1 << 13)):
        raise TelegramTlError("TL_UNSUPPORTED_NESTED")
    result = {"id": reader.i32(), "from_peer": None, "out": bool(flags & 2),
              "constructor": f"0x{constructor:08x}", "layer": layer,
              "record_kind": "tl_message", "validation": "supported_structure_complete"}
    if result["id"] == 0:
        raise TelegramTlError("TL_INVALID_MESSAGE_ID")
    if flags & 256:
        if layer == 118:
            sender = _nonnegative(reader.i32())
            result["from_peer"] = {"kind": "user", "id": sender} if sender else None
        else:
            result["from_peer"] = _peer(reader, allow_zero=True)
    if flags & (1 << 29):
        result["from_boosts_applied"] = _nonnegative(reader.i32())
    if flags2 & (1 << 12):
        result["from_rank"] = reader.string()
    result["peer"] = _peer(reader)
    if flags & (1 << 28):
        result["saved_peer"] = _peer(reader)
    if flags & 4:
        result["forward"] = _forward(reader)
    if flags & (1 << 11):
        result["via_bot_id"] = _nonnegative(reader.i64() if layer >= 135 else reader.i32())
    if flags2 & 1:
        result["via_business_bot_id"] = _nonnegative(reader.i64())
    if flags2 & (1 << 19):
        result["guestchat_via_from"] = _peer(reader)
    if flags & 8:
        result["reply"] = {"message_id": reader.i32()} if layer == 118 else _reply(reader)
    result["date"] = _nonnegative(reader.i32())
    result["text"] = reader.string()
    if flags & 512:
        result["media"] = _media(reader)
    if flags & 64:
        _markup(reader)
    if flags & 128:
        result["entities"] = _entities(reader, result["text"])
    if flags & 1024:
        result["views"], result["forwards"] = _nonnegative(reader.i32()), _nonnegative(reader.i32())
    if flags & (1 << 23):
        result["replies"] = _replies(reader)
    if flags & (1 << 15):
        result["edit_date"] = _nonnegative(reader.i32())
    if flags & (1 << 16):
        result["post_author"] = reader.string()
    if flags & (1 << 17):
        result["grouped_id"] = reader.i64()
    if flags & (1 << 22):
        result["restrictions"] = _restrictions(reader)
    if flags & (1 << 25):
        result["ttl_period"] = _nonnegative(reader.i32())
    if flags & (1 << 30):
        result["quick_reply_shortcut_id"] = reader.i32()
    if flags2 & (1 << 2):
        result["effect"] = reader.i64()
    if flags2 & (1 << 5):
        result["report_delivery_until_date"] = _nonnegative(reader.i32())
    if flags2 & (1 << 6):
        result["paid_message_stars"] = _nonnegative(reader.i64())
    if flags2 & (1 << 10):
        result["schedule_repeat_period"] = _nonnegative(reader.i32())
    if flags2 & (1 << 11):
        result["summary_from_language"] = reader.string()
    result["tl_bytes"] = reader.at
    result["local_tail_present"] = False
    if reader.at < len(blob):
        reader.string()  # opaque Android attachPath; never resolve it
        result["local_tail_present"] = True
        if flags & 4 and result["id"] < 0:
            reader.i32()
    if reader.at != len(blob):
        raise TelegramTlError("TL_UNSUPPORTED_TRAILING_BYTES")
    result["consumed_bytes"] = reader.at
    return result
