from types import SimpleNamespace

from localstack.services.ssm.provider import SsmProvider


def test_put_parameter_emits_create_then_update(monkeypatch):
    """
    Ensure put_parameter emits 'Create' on initial put and 'Update' on overwrite.
    We stub out moto calls and capture the emitted operations.
    """

    provider = SsmProvider()
    operations: list[str] = []

    # simulate moto returning incrementing versions for consecutive puts
    versions = [1, 2]

    def fake_call_moto(context):
        return {"Version": versions.pop(0)}

    # the code may use either call_moto or call_moto_with_request depending on normalization
    monkeypatch.setattr("localstack.services.ssm.provider.call_moto", fake_call_moto)
    monkeypatch.setattr("localstack.services.ssm.provider.call_moto_with_request", fake_call_moto)

    monkeypatch.setattr(
        SsmProvider,
        "_notify_event_subscribers",
        lambda account_id, region, name, operation: operations.append(operation),
    )

    ctx = SimpleNamespace(account_id="000000000000", region="us-east-1")
    request = {"Name": "/test/param", "Value": "v1", "Type": "String", "Overwrite": False}

    provider.put_parameter(ctx, request.copy())
    request["Value"] = "v2"
    request["Overwrite"] = True
    provider.put_parameter(ctx, request.copy())

    assert operations == ["Create", "Update"]
