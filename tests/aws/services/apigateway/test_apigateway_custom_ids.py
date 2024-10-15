from moto.apigateway.utils import (
    ApigwApiKeyIdentifier,
    ApigwResourceIdentifier,
    ApigwRestApiIdentifier,
)

from localstack.testing.pytest import markers
from localstack.utils.strings import long_uid, short_uid

API_ID = "ApiId"
ROOT_RESOURCE_ID = "RootId"
PET_1_RESOURCE_ID = "Pet1Id"
PET_2_RESOURCE_ID = "Pet2Id"
API_KEY_ID = "ApiKeyId"


# Custom ids can't be set on aws.
@markers.aws.only_localstack
def test_apigateway_custom_ids(
    aws_client, set_resource_custom_id, create_rest_apigw, account_id, region_name, cleanups
):
    rest_api_name = f"apigw-{short_uid()}"
    api_key_value = long_uid()

    set_resource_custom_id(ApigwRestApiIdentifier(account_id, region_name, rest_api_name), API_ID)
    set_resource_custom_id(
        ApigwResourceIdentifier(account_id, region_name, path_name="/"), ROOT_RESOURCE_ID
    )
    set_resource_custom_id(
        ApigwResourceIdentifier(
            account_id, region_name, parent_id=ROOT_RESOURCE_ID, path_name="pet"
        ),
        PET_1_RESOURCE_ID,
    )
    set_resource_custom_id(
        ApigwResourceIdentifier(
            account_id, region_name, parent_id=PET_1_RESOURCE_ID, path_name="pet"
        ),
        PET_2_RESOURCE_ID,
    )
    set_resource_custom_id(
        ApigwApiKeyIdentifier(account_id, region_name, value=api_key_value), API_KEY_ID
    )

    api_id, name, root_id = create_rest_apigw(name=rest_api_name)
    pet_resource_1 = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=ROOT_RESOURCE_ID, pathPart="pet"
    )
    # we create a second resource with the same path part to ensure we can pass different ids
    pet_resource_2 = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=PET_1_RESOURCE_ID, pathPart="pet"
    )
    api_key = aws_client.apigateway.create_api_key(name="api-key", value=api_key_value)
    cleanups.append(lambda: aws_client.apigateway.delete_api_key(apiKey=api_key["id"]))

    assert api_id == API_ID
    assert name == rest_api_name
    assert root_id == ROOT_RESOURCE_ID
    assert pet_resource_1["id"] == PET_1_RESOURCE_ID
    assert pet_resource_2["id"] == PET_2_RESOURCE_ID
    assert api_key["id"] == API_KEY_ID
