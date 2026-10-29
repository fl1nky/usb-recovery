"""Bounded Unicode literal/regex matching shared by archive and dump readers."""
import time


class MatchError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Matcher:
    def __init__(self, query="", mode="literal"):
        if not isinstance(query, str) or len(query) > 1024 or mode not in ("literal", "regex"):
            raise MatchError("INVALID_REQUEST")
        self.terms = query.casefold().split()
        if mode == "literal" and len(self.terms) > 32:
            raise MatchError("QUERY_TOO_LONG")
        self.pattern = None
        self.remaining = 5.0
        if mode == "regex" and query:
            import regex
            try:
                self.pattern = regex.compile(query, regex.IGNORECASE | regex.VERSION1)
            except (regex.error, OverflowError, RuntimeError):
                raise MatchError("REGEX_INVALID") from None

    def matches(self, text):
        if self.pattern is None:
            return all(term in text.casefold() for term in self.terms)
        if self.remaining <= 0:
            raise MatchError("REGEX_TIMEOUT")
        start = time.monotonic()
        try:
            return self.pattern.search(text, timeout=min(0.05, self.remaining)) is not None
        except TimeoutError:
            raise MatchError("REGEX_TIMEOUT") from None
        finally:
            self.remaining -= time.monotonic() - start
