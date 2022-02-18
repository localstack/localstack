import multiprocessing
import threading
from queue import Queue

from localstack.utils.analytics.metadata import get_client_metadata, get_session_id


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
