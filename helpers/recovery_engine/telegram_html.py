"""Text-only readers for provided local HTML exports; never execute markup."""
from html.parser import HTMLParser


# HTML void elements never create a container, including their XHTML spelling.
# HTMLParser's default start/end handler calls both callbacks for <br/>.
VOID_ELEMENTS = frozenset({
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link',
    'meta', 'param', 'source', 'track', 'wbr',
})

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
        if tag in VOID_ELEMENTS:
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
        if tag in VOID_ELEMENTS:
            return
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

