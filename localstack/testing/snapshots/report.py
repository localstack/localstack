import logging

from localstack.testing.snapshots import SnapshotMatchResult

LOG = logging.getLogger(__file__)

_esctable = dict(
    # text colors
    black=30,
    red=31,
    green=32,
    yellow=33,
    blue=34,
    purple=35,
    cyan=36,
    white=37,
    # background colors
    Black=40,
    Red=41,
    Green=42,
    Yellow=43,
    Blue=44,
    Purple=45,
    Cyan=46,
    White=47,
    # special
    bold=1,
    light=2,
    blink=5,
    invert=7,
    strikethrough=9,
    underlined=4,
)


class PatchPath(str):
    """
    used to wrap a path string to compare hierarchically & lexically by going through
    each path level
    """

    def __lt__(self, other):
        if not isinstance(other, PatchPath):
            raise ValueError("Incompatible types")

        parts = zip(self.split("/"), other.split("/"))
        for (sa, sb) in parts:
            if sa < sb:
                return True

        return False


def render_report(result: SnapshotMatchResult):
    def _line(c) -> [(str, str)]:
        def _render_path_part(part):
            if isinstance(part, int):
                return f"[{part}]"  # wrap iterable index in [] to more clearly denote it being such
            return str(part)

        path_parts = [_render_path_part(p) for p in c.path(output_format="list")]
        change_path = "/" + "/".join(path_parts)

        expected = c.t1
        actual = c.t2

        if c.report_type in [
            "dictionary_item_removed",
        ]:
            return [(change_path, f"[remove](-)[/remove] {change_path} ( {expected!r} )")]
        elif c.report_type in ["iterable_item_removed"]:
            if actual:
                # seems to be a bug with deepdiff, if there's the same number of items in the iterable and one differs
                # it will report the missing one but won't report the "additional" on the corresponding position
                return [
                    (change_path, f"[remove](-)[/remove] {change_path} ( {expected!r} )"),
                    (change_path, f"[add](+)[/add] {change_path} ( {actual!r} )"),
                ]
            return [(change_path, f"[remove](-)[/remove] {change_path} ( {expected!r} )")]
        elif c.report_type in ["dictionary_item_added", "iterable_item_added"]:
            return [(change_path, f"[add](+)[/add] {change_path} ( {actual!r} )")]
        elif c.report_type in ["values_changed"]:
            # TODO: more fancy change detection and visualization (e.g. parts of a string)
            return [
                (
                    change_path,
                    f"[replace](~)[/replace] {change_path} {expected!r} → {actual!r} ... (expected → actual)",
                )
            ]
        else:
            LOG.warning(
                f"Unsupported diff mismatch reason: {c.report_type}. Please report this to the team so we can add support. {expected=} | {actual=}"
            )
        return []

    lines = []
    for cat, changes in result.result.tree.items():
        for change in changes:
            lines.extend(_line(change))

    printstr = f">> match key: {result.key}\n"

    for (a, b) in sorted(lines, key=lambda x: PatchPath(x[0])):
        printstr += f"\t{b}\n"

    # you can add more entries to the lists to combine effects (e.g. red & underlined)
    replacement_map = {
        "remove": [_esctable["red"]],
        "add": [_esctable["green"]],
        "replace": [_esctable["yellow"]],
        "s": [_esctable["strikethrough"]],
    }

    # replace [x] tokens with the corresponding codes
    for token, replacements in replacement_map.items():
        printstr = printstr.replace(f"[{token}]", "".join(f"\x1b[{code}m" for code in replacements))
        printstr = printstr.replace(f"[/{token}]", "\x1b[0m")

    return printstr
