from typing import Any, Union


def format_number(number: float, decimals: int = 2):
    # Note: interestingly, f"{number:.3g}" seems to yield incorrect results in some cases.
    # The logic below seems to be the most stable/reliable.
    result = f"{number:.{decimals}f}"
    if "." in result:
        result = result.rstrip("0").rstrip(".")
    return result


def is_number(s: Any) -> bool:
    try:
        float(s)  # for int, long and float
        return True
    except (TypeError, ValueError):
        return False


def to_number(s: Any) -> Union[int, float]:
    """Cast the string representation of the given object to a number (int or float), or raise ValueError."""
    try:
        return int(str(s))
    except ValueError:
        return float(str(s))


def format_bytes(count: float, default: str = "n/a"):
    """Format a bytes number as a human-readable unit, e.g., 1.3GB or 21.53MB"""
    if not is_number(count):
        return default
    cnt = float(count)
    if cnt < 0:
        return default
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if cnt < 1000 or unit == units[-1]:
            # FIXME: will return '1e+03TB' for 1000TB
            return f"{format_number(cnt, decimals=3)}{unit}"
        cnt = cnt / 1000.0
    return count
