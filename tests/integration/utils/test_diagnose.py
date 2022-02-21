import requests

from localstack import config


def test_diagnose_endpoint():
    # simple smoke test diagnose endpoint

    result = requests.get(f"{config.get_edge_url()}/_localstack/diagnose").json()

    assert "/tmp" in result["file-tree"]
    assert "/var/lib/localstack" in result["file-tree"]
    assert result["config"]["EDGE_PORT"] == config.EDGE_PORT
    assert result["config"]["DATA_DIR"] == config.DATA_DIR
    assert result["important-endpoints"]["localhost.localstack.cloud"].startswith("127.0.")
    assert result["logs"]["docker"]
