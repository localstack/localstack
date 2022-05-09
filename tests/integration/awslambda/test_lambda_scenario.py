import json
import os
import tempfile
import zipfile

import aws_cdk as cdk
import pulumi
import pytest
from pulumi.automation._config import ConfigValue
from pulumi.automation._local_workspace import LocalWorkspaceOptions
from pulumi_aws import iam, lambda_, sqs

from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until

FN_CODE = """
import json

def handler(event, ctx):
    print(json.dumps(event))
    return {"a": "b"}
"""


class TestLambdaSqsEventSource:
    @pytest.fixture(scope="class")
    def localstack_config_map(self):
        cm = {}
        if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
            # default values should be fine
            pass
        else:
            cm["aws:region"] = ConfigValue(value="us-east-1")
            cm["aws:s3ForcePathStyle"] = ConfigValue(value="true")
            cm["aws:secretKey"] = ConfigValue(value="test")
            cm["aws:accessKey"] = ConfigValue(value="test")
            cm["aws:skipCredentialsValidation"] = ConfigValue(value="true")
            cm["aws:skipRequestingAccountId"] = ConfigValue(value="true")

            # set all endpoints TODO
            cm["aws:endpoints"] = ConfigValue(
                value="["
                '{"lambda": "http://localhost:4566"},'
                '{"iam": "http://localhost:4566"},'
                '{"sqs": "http://localhost:4566"},'
                '{"s3": "http://localhost:4566"}]'
            )

        return cm

    def create_pulumi_lambda_asset_from_inline_code(self, inline_code):
        tmpdir = tempfile.mkdtemp()
        zip_fn = os.path.join(tmpdir, "index.zip")
        zip_obj = zipfile.ZipFile(zip_fn, "w")

        with tempfile.NamedTemporaryFile("w") as tmp:
            tmp.write(inline_code)  # TODO
            tmp.seek(0)
            try:
                zip_obj.write(tmp.name, os.path.basename("index.py"))
            except Exception as e:
                print(e)

        return zip_fn
        # TODO where/when clean up
        # try:
        #     shutil.rmtree(tmpdir)  # delete directory
        # except Exception:
        #     pass  # TODO

    def pulumi_program(self):
        try:
            iam_for_lambda = iam.Role(
                "iamForLambda",
                assume_role_policy="""{
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Action": "sts:AssumeRole",
                  "Principal": {
                    "Service": "lambda.amazonaws.com"
                  },
                  "Effect": "Allow",
                  "Sid": ""
                }
              ]
            }
            """,
            )
            if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
                # TODO - policies required for AWS
                iam.RolePolicyAttachment(
                    "lambda_role_attachment",
                    role=pulumi.Output.concat(iam_for_lambda.name),
                    policy_arn="arn:aws:iam::aws:policy/AWSLambda_FullAccess",
                )
                iam.RolePolicyAttachment(
                    "lambda_role_attachment_sqs",
                    role=pulumi.Output.concat(iam_for_lambda.name),
                    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole",
                )

            zipped_lambda = self.create_pulumi_lambda_asset_from_inline_code(inline_code=FN_CODE)
            file_archive = pulumi.FileArchive(zipped_lambda)

            aws_lambda = lambda_.Function(
                "test-lambda",
                code=file_archive,
                handler="index.handler",
                runtime="python3.8",
                role=iam_for_lambda.arn,
            )

            aws_sqs_queue = sqs.Queue("myqueue")

            event_source_mapping = lambda_.EventSourceMapping(
                "my-event-source-mapping",
                event_source_arn=aws_sqs_queue.arn,
                function_name=aws_lambda.arn,
                batch_size=1,
            )

            pulumi.export("QueueUrlOutput", aws_sqs_queue.url)
            pulumi.export("FnNameOutput", aws_lambda.name)
            pulumi.export("ESMIdOutput", event_source_mapping.id)

        finally:
            pass
            # TODO we cannot delete file immediately, test will fail
            # try:
            #      shutil.rmtree(os.path.abspath(os.path.join(zipped_lambda, os.pardir)))  # delete directory
            # except Exception:
            #      pass  # TODO

    @pytest.fixture(scope="class")
    def stack_pulumi(self, localstack_config_map):
        stack_reference_list = []

        def _create_stack(**kwargs):
            project_name = kwargs.get("project_name", f"project-{short_uid()}")
            stack_name = kwargs.get("stack_name", f"stack-{short_uid()}")
            pulumi_program = kwargs["pulumi_program"]

            # TODO set env "PULUMI_TEST_MODE": "true"
            my_settings = LocalWorkspaceOptions(
                env_vars={"PULUMI_CONFIG_PASSPHRASE": "test", "PULUMI_BACKEND_URL": "file://~"}
            )
            stack = pulumi.automation.create_or_select_stack(
                stack_name=stack_name,
                project_name=project_name,
                program=pulumi_program,
                opts=my_settings,
            )
            stack.workspace.install_plugin("aws", "v4.0.0")
            stack.set_all_config(localstack_config_map)
            stack.refresh(on_output=print)
            up_res = stack.up(on_output=print)  # TODO verify something?
            stack_reference_list.append(stack)
            return up_res

        yield _create_stack

        for stack in stack_reference_list:
            stack.destroy(on_output=print)

    # setup (1x cloudformation, 1x SDK based)
    # can be switched between "fucntion" and "class" scope depending on what behavior you need
    # try to use class where possible
    # if CI encounters an error here with a "class" scoped fixture it can retry using "function" scope (? implementation ?)
    @pytest.fixture(scope="function")  # TODO: remove fixture dependency and make class scoped
    def stack_cdk(self, deploy_cfn_template):
        app = cdk.App()
        stack = cdk.Stack(app, "Stack")

        queue = cdk.aws_sqs.Queue(stack, "myqueue")
        fn = cdk.aws_lambda.Function(
            stack,
            "fn",
            code=cdk.aws_lambda.InlineCode(FN_CODE),
            runtime=cdk.aws_lambda.Runtime.PYTHON_3_8,
            handler="index.handler",
        )
        event_source = cdk.aws_lambda_event_sources.SqsEventSource(queue=queue, batch_size=1)
        fn.add_event_source(event_source)

        cdk.CfnOutput(stack, "QueueUrlOutput", value=queue.queue_url)
        cdk.CfnOutput(stack, "FnNameOutput", value=fn.function_name)
        cdk.CfnOutput(stack, "ESMIdOutput", value=event_source.event_source_mapping_id)

        rendered_template = cdk.assertions.Template.from_stack(stack).to_json()
        deploy_cfn_template(template_file_name="cdk_bootstrap_v10.yaml")

        yield deploy_cfn_template(template=json.dumps(rendered_template))

    def test_simple(self, stack_pulumi):
        res = stack_pulumi(
            project_name="hello", stack_name="hey", pulumi_program=self.pulumi_program
        )
        print(f"{res.outputs['QueueUrlOutput'].value}")

    def test_resource_states_pulumi(self, stack_pulumi, lambda_client, sqs_client, snapshot):
        res = stack_pulumi(
            project_name="scenario-test", stack_name="my-stack", pulumi_program=self.pulumi_program
        )
        outputs = res.outputs
        snapshot.match(
            "queue-attributes",
            sqs_client.get_queue_attributes(QueueUrl=outputs["QueueUrlOutput"].value),
        )
        snapshot.match(
            "lambda-get-function",
            lambda_client.get_function(FunctionName=outputs["FnNameOutput"].value),
        )
        snapshot.match(
            "esm-get", lambda_client.get_event_source_mapping(UUID=outputs["ESMIdOutput"].value)
        )

    def test_resource_states(self, stack_cdk, lambda_client, sqs_client, snapshot):
        snapshot.match(
            "queue-attributes",
            sqs_client.get_queue_attributes(QueueUrl=stack_cdk.outputs["QueueUrlOutput"]),
        )
        snapshot.match(
            "lambda-get-function",
            lambda_client.get_function(FunctionName=stack_cdk.outputs["FnNameOutput"]),
        )
        snapshot.match(
            "esm-get", lambda_client.get_event_source_mapping(UUID=stack_cdk.outputs["ESMIdOutput"])
        )

    def test_message_triggers_lambda(self, stack_cdk, lambda_client, sqs_client, logs_client):
        sqs_client.send_message(
            QueueUrl=stack_cdk.outputs["QueueUrlOutput"], MessageBody="test-1234"
        )

        # todo create better utils for call verifications
        def check_logs():
            return any(
                "test-1234" in e["message"]
                for e in logs_client.filter_log_events(
                    logGroupName=f'/aws/lambda/{stack_cdk.outputs["FnNameOutput"]}'
                )["events"]
            )

        assert wait_until(check_logs)

    def test_message_triggers_lambda_pulumi(
        self, stack_pulumi, lambda_client, sqs_client, logs_client
    ):
        res = stack_pulumi(
            project_name="scenario-test", stack_name="my-stack", pulumi_program=self.pulumi_program
        )
        outputs = res.outputs
        sqs_client.send_message(QueueUrl=outputs["QueueUrlOutput"].value, MessageBody="test-1234")

        # todo create better utils for call verifications
        def check_logs():
            return any(
                "test-1234" in e["message"]
                for e in logs_client.filter_log_events(
                    logGroupName=f'/aws/lambda/{outputs["FnNameOutput"].value}'
                )["events"]
            )

        assert wait_until(check_logs)
