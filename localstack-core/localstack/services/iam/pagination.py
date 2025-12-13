"""
Pagination utilities for IAM list operations.

IAM uses marker-based pagination where:
- `Marker`: A token indicating where to start the next page
- `MaxItems`: Maximum items to return (default varies by operation)
- `IsTruncated`: Boolean indicating if there are more results
- Response `Marker`: Token for the next page (only present if truncated)
"""

from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")

# Default page sizes for different IAM operations
DEFAULT_MAX_ITEMS = 100
DEFAULT_MAX_ITEMS_USERS = 100
DEFAULT_MAX_ITEMS_ROLES = 100
DEFAULT_MAX_ITEMS_GROUPS = 100
DEFAULT_MAX_ITEMS_POLICIES = 100
DEFAULT_MAX_ITEMS_ACCESS_KEYS = 100


class PaginatedResults:
    """
    Container for paginated results.

    Attributes:
        items: The items for the current page
        is_truncated: Whether there are more items
        next_marker: Marker for the next page (None if not truncated)
    """

    def __init__(
        self,
        items: list[Any],
        is_truncated: bool = False,
        next_marker: Optional[str] = None,
    ):
        self.items = items
        self.is_truncated = is_truncated
        self.next_marker = next_marker

    def to_response_dict(
        self,
        items_key: str,
        marker_key: str = "Marker",
        truncated_key: str = "IsTruncated",
    ) -> dict:
        """
        Convert to a response dictionary suitable for AWS API responses.

        :param items_key: Key name for the items list (e.g., "Users", "Roles")
        :param marker_key: Key name for the marker (default: "Marker")
        :param truncated_key: Key name for truncation flag (default: "IsTruncated")
        :return: Dictionary with items, truncation flag, and optionally marker
        """
        result = {
            items_key: self.items,
            truncated_key: self.is_truncated,
        }
        if self.is_truncated and self.next_marker:
            result[marker_key] = self.next_marker
        return result


def paginate_list(
    items: list[T],
    marker: Optional[str] = None,
    max_items: Optional[int] = None,
    get_marker_value: Optional[Callable[[T], str]] = None,
    default_max_items: int = DEFAULT_MAX_ITEMS,
) -> PaginatedResults:
    """
    Paginate a list of items using marker-based pagination.

    This implements AWS-style marker pagination where:
    1. If a marker is provided, find the item after that marker
    2. Return up to max_items starting from that position
    3. If there are more items, return is_truncated=True and the next marker

    :param items: Full list of items to paginate
    :param marker: Starting marker (name/id of the last item from previous page)
    :param max_items: Maximum items to return (uses default_max_items if None)
    :param get_marker_value: Function to extract marker value from an item
                            If None, items are assumed to be strings
    :param default_max_items: Default page size if max_items is None
    :return: PaginatedResults with items for the current page
    """
    if not items:
        return PaginatedResults(items=[], is_truncated=False)

    # Determine actual max items (cap at 1000 as AWS does)
    actual_max_items = min(max_items or default_max_items, 1000)

    # Find starting index
    start_idx = 0
    if marker:
        # Find the item with the marker value
        for i, item in enumerate(items):
            item_marker = get_marker_value(item) if get_marker_value else item
            if item_marker == marker:
                start_idx = i + 1  # Start after the marker item
                break

    # Get the page of items
    end_idx = start_idx + actual_max_items
    page_items = items[start_idx:end_idx]

    # Determine if truncated and next marker
    is_truncated = end_idx < len(items)
    next_marker = None
    if is_truncated and page_items:
        last_item = page_items[-1]
        next_marker = get_marker_value(last_item) if get_marker_value else last_item

    return PaginatedResults(
        items=page_items,
        is_truncated=is_truncated,
        next_marker=next_marker,
    )


def paginate_dict(
    items: dict[str, T],
    marker: Optional[str] = None,
    max_items: Optional[int] = None,
    sort_key: Optional[Callable[[tuple[str, T]], Any]] = None,
    default_max_items: int = DEFAULT_MAX_ITEMS,
) -> PaginatedResults:
    """
    Paginate a dictionary of items using marker-based pagination.

    Items are sorted by key (or custom sort_key) before pagination.
    The marker is the dictionary key of the last item.

    :param items: Dictionary of items to paginate (key -> item)
    :param marker: Starting marker (key of the last item from previous page)
    :param max_items: Maximum items to return
    :param sort_key: Custom sort function for (key, value) tuples
    :param default_max_items: Default page size if max_items is None
    :return: PaginatedResults with items for the current page (values only)
    """
    if not items:
        return PaginatedResults(items=[], is_truncated=False)

    # Sort items by key (or custom sort)
    sorted_items = sorted(items.items(), key=sort_key or (lambda x: x[0]))

    # Determine actual max items
    actual_max_items = min(max_items or default_max_items, 1000)

    # Find starting index
    start_idx = 0
    if marker:
        for i, (key, _) in enumerate(sorted_items):
            if key == marker:
                start_idx = i + 1
                break

    # Get the page of items
    end_idx = start_idx + actual_max_items
    page = sorted_items[start_idx:end_idx]
    page_items = [item for _, item in page]

    # Determine if truncated and next marker
    is_truncated = end_idx < len(sorted_items)
    next_marker = None
    if is_truncated and page:
        next_marker = page[-1][0]  # Key of the last item

    return PaginatedResults(
        items=page_items,
        is_truncated=is_truncated,
        next_marker=next_marker,
    )


def filter_by_path_prefix(
    items: list[T],
    path_prefix: Optional[str],
    get_path: Callable[[T], str],
) -> list[T]:
    """
    Filter items by path prefix.

    :param items: List of items to filter
    :param path_prefix: Path prefix to filter by (None means no filter)
    :param get_path: Function to extract path from an item
    :return: Filtered list of items
    """
    if not path_prefix:
        return items

    # Normalize path prefix
    if not path_prefix.startswith("/"):
        path_prefix = "/" + path_prefix

    return [item for item in items if get_path(item).startswith(path_prefix)]


def filter_by_scope(
    items: list[T],
    scope: Optional[str],
    is_aws_managed: Callable[[T], bool],
) -> list[T]:
    """
    Filter policies by scope (All, AWS, Local).

    :param items: List of policies to filter
    :param scope: Scope filter ("All", "AWS", "Local", or None for All)
    :param is_aws_managed: Function to check if policy is AWS managed
    :return: Filtered list of policies
    """
    if not scope or scope == "All":
        return items

    if scope == "AWS":
        return [item for item in items if is_aws_managed(item)]
    elif scope == "Local":
        return [item for item in items if not is_aws_managed(item)]

    return items
