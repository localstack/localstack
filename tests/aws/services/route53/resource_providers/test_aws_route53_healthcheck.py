import os

from localstack.testing.pytest import markers


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=["$..HealthCheckConfig.EnableSNI", "$..HealthCheckVersion"]
)
def test_create_health_check(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__),
            "../../../templates/route53_healthcheck.yml",
        ),
    )
    health_check_id = stack.outputs["HealthCheckId"]
    health_check = aws_client.route53.get_health_check(HealthCheckId=health_check_id)

    snapshot.add_transformer(snapshot.transform.key_value("Id", "id"))
    snapshot.add_transformer(snapshot.transform.key_value("CallerReference", "caller-reference"))
    snapshot.match("HealthCheck", health_check["HealthCheck"])
