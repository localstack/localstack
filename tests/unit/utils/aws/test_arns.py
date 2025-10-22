from localstack.utils.aws import arns


def test_arn_creation_with_colon_names():
    region_name = "us-east-1"
    account_id = "123456789012"
    name = "noColons"
    name_colon = "col:on"
    pattern = "arn:%s:<service>:%s:%s:thing/%s"

    assert (
        arns._resource_arn(name, pattern, account_id, region_name)
        == f"arn:aws:<service>:{region_name}:{account_id}:thing/{name}"
    )
    assert arns._resource_arn(name_colon, pattern, account_id, region_name) == name_colon
    assert (
        arns._resource_arn(name_colon, pattern, account_id, region_name, True)
        == f"arn:aws:<service>:{region_name:}:{account_id}:thing/{name_colon}"
    )
