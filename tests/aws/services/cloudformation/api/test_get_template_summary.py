import os

from localstack.testing.pytest import markers


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=["$..ResourceIdentifierSummaries..ResourceIdentifiers"]
)
def test_get_template_summary(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.sns_api())

    deployment = deploy_cfn_template(
        template_path=os.path.join(
            # This template has no parameters, and so shows the issue
            os.path.dirname(__file__),
            "../../../templates/sns_topic_simple.yaml",
        )
    )

    res = aws_client.cloudformation.get_template_summary(StackName=deployment.stack_name)

    snapshot.match("template-summary", res)
