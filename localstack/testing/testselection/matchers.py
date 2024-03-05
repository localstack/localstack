import fnmatch
import re
from typing import Callable

SENTINEL_NO_TEST = "SENTINEL_NO_TEST"  # a line item which signals that we don't default to everything, we just don't want to actually want to run a test => useful to differentiate between empty / nothing
SENTINEL_ALL_TESTS = "SENTINEL_ALL_TESTS"  # a line item which signals that we don't default to everything, we just don't want to actually want to run a test => useful to differentiate between empty / nothing

Matcher = Callable[[str], bool]
MatchingRule = Callable[[str], list[str]]


class Matchers:
    @staticmethod
    def glob(glob: str) -> Matcher:
        return lambda t: fnmatch.fnmatch(t, glob)

    @staticmethod
    def regex(regex: str) -> Matcher:
        return lambda t: bool(re.match(regex, t))

    @staticmethod
    def extension(extension: str) -> Matcher:
        return Matchers.glob(f"*.{extension}")


class Rules:
    @staticmethod
    def full_suite(matcher: Matcher) -> MatchingRule:
        return lambda t: [SENTINEL_ALL_TESTS] if matcher(t) else []

    @staticmethod
    def ignore(matcher: Matcher) -> MatchingRule:
        return lambda t: [SENTINEL_NO_TEST] if matcher(t) else []


MATCHING_RULES: list[MatchingRule] = [
    # sample_custom_matcher,
    Rules.full_suite(Matchers.glob(".github")),
    Rules.ignore(Matchers.glob("**/.md")),
]
