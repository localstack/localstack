import json
import logging
import os

import pytest
import requests as requests

from localstack.utils.files import load_file

LOG = logging.getLogger(__name__)


class TestShoppingCartScenario:
    product_api: str
    cart_api: str

    @pytest.fixture(scope="class", autouse=True)
    def infra_setup(
        self, s3_create_bucket_class_scope, deploy_cfn_template_class_scope, aws_client
    ):
        # TODO hardcoded for now
        bucket_name = "aws-serverless-shopping-cart-src-000000000000-us-east-1"
        s3_create_bucket_class_scope(Bucket=bucket_name)
        resource1 = "31b17a7f0702ecfb30a6061d21a611bf"
        resource2 = "403bbd994f7d9248a24ce550fb517592"
        aws_client.s3.put_object(
            Bucket=bucket_name, Key=resource1, Body=load_file(f"./resources/{resource1}", mode="rb")
        )
        aws_client.s3.put_object(
            Bucket=bucket_name, Key=resource2, Body=load_file(f"./resources/{resource2}", mode="rb")
        )

        deploy_cfn_template_class_scope(
            template_path=os.path.join(
                os.path.dirname(__file__), "./resources/sam-package-output-auth.yml"
            ),
            max_wait=200,
        )
        result = deploy_cfn_template_class_scope(
            template_path=os.path.join(
                os.path.dirname(__file__), "./resources/sam-package-output-product-mock.yml"
            ),
            max_wait=200,
        )
        type(self).product_api = result.outputs["ProductApi"]

        result = deploy_cfn_template_class_scope(
            template_path=os.path.join(
                os.path.dirname(__file__), "./resources/sam-package-output-shoppingcart-service.yml"
            ),
            max_wait=200,
        )
        type(self).cart_api = result.outputs["CartApi"]

    def test_shopping_cart_verify_setup(self, aws_client):
        result = aws_client.awslambda.list_functions()
        assert len(result["Functions"]) == 10

        result = aws_client.cognito_idp.list_user_pools(MaxResults=100)
        assert len(result["UserPools"]) == 1

        result = aws_client.dynamodb.list_tables()
        assert len(result["TableNames"]) == 1

        result = aws_client.apigateway.get_rest_apis()
        assert len(result["items"]) == 2

        cart_api_id = [item for item in result["items"] if "CartApi" in item["name"]][0]["id"]
        result = aws_client.apigateway.get_authorizers(restApiId=cart_api_id)
        assert len(result["items"]) == 1

        result = aws_client.apigateway.get_resources(restApiId=cart_api_id)
        actual_paths = [item["path"] for item in result["items"]]
        actual_paths.sort()
        expected_paths = [
            "/",
            "/cart",
            "/cart/checkout",
            "/cart/migrate",
            "/cart/{product_id}",
            "/cart/{product_id}/total",
        ]

        assert actual_paths == expected_paths

    def test_list_products(self, aws_client):
        list_products = f"{self.product_api}/product"
        response = requests.get(list_products)
        assert response.status_code == 200

        products = json.loads(response.text)["products"]
        assert len(products) == 20
        expected_attributes = [
            "category",
            "createdDate",
            "description",
            "modifiedDate",
            "name",
            "package",
            "pictures",
            "price",
            "productId",
            "tags",
        ]
        assert all([True if expected_attributes == list(p.keys()) else False for p in products])

        selected_prod = products[4]
        selected_prod_id = selected_prod["productId"]

        response = requests.get(f"{list_products}/{selected_prod_id}")
        assert response.status_code == 200
        assert json.loads(response.text)["product"] == selected_prod

    def test_put_items_to_cart_unauthorized(self, aws_client):
        # TODO add_to_cart is not working :(
        pass
