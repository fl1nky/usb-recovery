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
            if not self.terms:
                return True
            folded = text.casefold()
            return all(term in folded for term in self.terms)
        return self._regex_search(text) is not None

    def first_span(self, text):
        """Locate an actual match in original Unicode code-point coordinates."""
        if self.pattern is not None:
            found = self._regex_search(text)
            return found.span() if found is not None else None
        if not self.terms:
            return 0, 0
        folded = text.casefold()
        start = folded.find(self.terms[0])
        if start < 0:
            return None
        stop, cursor, first = start + len(self.terms[0]), 0, None
        for index, char in enumerate(text):
            following = cursor + len(char.casefold())
            if first is None and following > start:
                first = index
            if following >= stop:
                return first, index + 1
            cursor = following
        return None

    def _regex_search(self, text):
        if self.remaining <= 0:
            raise MatchError("REGEX_TIMEOUT")
        start = time.monotonic()
        try:
            return self.pattern.search(text, timeout=min(0.05, self.remaining))
        except TimeoutError:
            raise MatchError("REGEX_TIMEOUT") from None
        finally:
            self.remaining -= time.monotonic() - start
