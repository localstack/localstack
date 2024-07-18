import sys
from itertools import islice
from typing import Any, Iterable, Iterator


def batched(iterable, n):
    # TODO: replace this method with native version when supporting Python 3.12
    #  https://docs.python.org/3.12/library/itertools.html#itertools.batched
    # batched('ABCDEFG', 3) --> ABC DEF G
    if n < 1:
        raise ValueError("n must be at least one")
    it = iter(iterable)
    while batch := tuple(islice(it, n)):
        yield batch


def batched_by_size(iterable: Iterable[Any], max_bytes) -> Iterator[tuple[Any, ...]]:
    """
    Generate batches from iterable where the total size of each batch in bytes does not exceed `max_bytes`.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be at least one")

    it = iter(iterable)
    while True:
        batch = []
        current_size = 0
        try:
            while current_size < max_bytes:
                item = next(it)
                item_size = sys.getsizeof(item)
                if current_size + item_size > max_bytes:
                    # If adding this item exceeds max_bytes, push it back onto the iterator and stop this batch
                    it = iter([item] + list(it))
                    break
                batch.append(item)
                current_size += item_size
        except StopIteration:
            pass

        if not batch:
            break
        yield tuple(batch)
