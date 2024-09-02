import multiprocessing
import os.path
import threading
from queue import Queue

import pytest

from localstack import config
from localstack.utils.analytics.metadata import (
    get_client_metadata,
    get_localstack_edition,
    get_session_id,
)


def test_get_client_metadata_cache():
    c1 = get_client_metadata()
    c2 = get_client_metadata()

    assert c1 is not None
    assert c2 is not None
    assert c1 is c2


def test_get_session_id_cache_not_thread_local():
    calls = Queue()

    def _do_get_session_id():
        calls.put(get_session_id())

    threading.Thread(target=_do_get_session_id).start()
    threading.Thread(target=_do_get_session_id).start()

    sid1 = calls.get(timeout=2)
    sid2 = calls.get(timeout=2)

    assert sid1 == sid2


def test_get_session_id_cache_not_process_local():
    calls = multiprocessing.Queue()

    def _do_get_session_id():
        calls.put(get_session_id())

    try:
        multiprocessing.Process(target=_do_get_session_id).start()
        multiprocessing.Process(target=_do_get_session_id).start()

        sid1 = calls.get(timeout=2)
        sid2 = calls.get(timeout=2)

        assert sid1 == sid2
    except AttributeError as e:
        # fix for MacOS (and potentially other systems) where local functions cannot be used for multiprocessing
        if "Can't pickle local object" not in str(e):
            raise


@pytest.mark.parametrize(
    "expected_edition, version_file",
    [
        ("enterprise", ".enterprise-version"),
        ("pro", ".pro-version"),
        ("community", ".community-version"),
        ("azure-alpha", ".azure-alpha-version"),
        ("unknown", "non-hidden-version"),
        ("unknown", ".hidden-file"),
        ("unknown", "not-a-version-file"),
    ],
)
def test_get_localstack_edition(expected_edition, version_file):
    # put the version file in the expected location
    file_location = os.path.join(config.dirs.static_libs, version_file)
    with open(file_location, "w") as f:
        f.write("")

    assert get_localstack_edition() == expected_edition

    # cleanup
    os.remove(file_location)
