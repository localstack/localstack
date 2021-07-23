from localstack.utils.analytics.metadata import get_client_metadata, get_session_id


def test_get_client_metadata_cache():
    c1 = get_client_metadata()
    c2 = get_client_metadata()

    assert c1 is not None
    assert c2 is not None
    assert c1 is c2


def test_get_session_id_cache():
    metadata = get_client_metadata()
    session_id = get_session_id()

    assert metadata.session_id == session_id
