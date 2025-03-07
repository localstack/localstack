"""
This file includes tests that reverse engineer the deployment process
by generating invalid templates and determining which error causes a
failure. We induce that all deployment processes are the same and
these steps are universal.
"""

import pytest
from botocore.exceptions import ClientError

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers

pytestmark = [pytest.mark.skipif(not is_aws_cloud(), reason="Exploratory tests only")]


@markers.aws.validated
def test_template_parsing_or_invalid_schema(deploy_cfn_template, snapshot):
    invalid_yaml_template = """
        lkjas:
    Foo:
        Bar: 10
    """

    with pytest.raises(ClientError) as exc_info:
        deploy_cfn_template(
            template=invalid_yaml_template,
        )

    snapshot.match("deploy-error", exc_info.value)
