import json

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.activities.activity_templates import (
    ActivityTemplate,
)


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestActivities:
    @markers.aws.validated
    def test_activity_task(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_activity,
        sfn_activity_consumer,
        sfn_snapshot,
    ):
        activity_name = f"activity-{short_uid()}"
        create_activity_output = create_activity(name=activity_name)
        activity_arn = create_activity_output["activityArn"]
        sfn_snapshot.add_transformer(RegexTransformer(activity_arn, "activity_arn"))
        sfn_snapshot.add_transformer(RegexTransformer(activity_name, "activity_name"))
        sfn_snapshot.match("create_activity_output", create_activity_output)

        sfn_activity_consumer(
            template=ActivityTemplate.load_sfn_template(ActivityTemplate.BASE_ID_ACTIVITY_CONSUMER),
            activity_arn=activity_arn,
        )

        template = ActivityTemplate.load_sfn_template(ActivityTemplate.BASE_ACTIVITY_TASK)
        template["States"]["ActivityTask"]["Resource"] = activity_arn
        definition = json.dumps(template)

        exec_input = json.dumps({"Value1": "HelloWorld"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_activity_task_no_worker_name(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_activity,
        sfn_activity_consumer,
        sfn_snapshot,
    ):
        activity_name = f"activity-{short_uid()}"
        create_activity_output = create_activity(name=activity_name)
        activity_arn = create_activity_output["activityArn"]
        sfn_snapshot.add_transformer(RegexTransformer(activity_arn, "activity_arn"))
        sfn_snapshot.add_transformer(RegexTransformer(activity_name, "activity_name"))
        sfn_snapshot.match("create_activity_output", create_activity_output)

        template_consumer = ActivityTemplate.load_sfn_template(
            ActivityTemplate.BASE_ID_ACTIVITY_CONSUMER
        )
        del template_consumer["States"]["GetActivityTask"]["Parameters"]["WorkerName"]
        sfn_activity_consumer(template=template_consumer, activity_arn=activity_arn)

        template = ActivityTemplate.load_sfn_template(ActivityTemplate.BASE_ACTIVITY_TASK)
        template["States"]["ActivityTask"]["Resource"] = activity_arn
        definition = json.dumps(template)

        exec_input = json.dumps({"Value1": "HelloWorld"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_activity_task_on_deleted(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_activity,
        sfn_snapshot,
    ):
        activity_name = f"activity-{short_uid()}"
        create_activity_output = create_activity(name=activity_name)
        activity_arn = create_activity_output["activityArn"]
        sfn_snapshot.add_transformer(RegexTransformer(activity_arn, "activity_arn"))
        sfn_snapshot.add_transformer(RegexTransformer(activity_name, "activity_name"))
        sfn_snapshot.match("create_activity_output", create_activity_output)

        aws_client.stepfunctions.delete_activity(activityArn=activity_arn)

        template = ActivityTemplate.load_sfn_template(ActivityTemplate.BASE_ACTIVITY_TASK)
        template["States"]["ActivityTask"]["Resource"] = activity_arn
        definition = json.dumps(template)

        exec_input = json.dumps({"Value1": "HelloWorld"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_activity_task_failure(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_activity,
        sfn_activity_consumer,
        sfn_snapshot,
    ):
        activity_name = f"activity-{short_uid()}"
        create_activity_output = create_activity(name=activity_name)
        activity_arn = create_activity_output["activityArn"]
        sfn_snapshot.add_transformer(RegexTransformer(activity_arn, "activity_arn"))
        sfn_snapshot.add_transformer(RegexTransformer(activity_name, "activity_name"))
        sfn_snapshot.match("create_activity_output", create_activity_output)

        sfn_activity_consumer(
            template=ActivityTemplate.load_sfn_template(
                ActivityTemplate.BASE_ID_ACTIVITY_CONSUMER_FAIL
            ),
            activity_arn=activity_arn,
        )

        template = ActivityTemplate.load_sfn_template(ActivityTemplate.BASE_ACTIVITY_TASK)
        template["States"]["ActivityTask"]["Resource"] = activity_arn
        definition = json.dumps(template)

        exec_input = json.dumps({"Value1": "HelloWorld"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_activity_task_with_heartbeat(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_activity,
        sfn_activity_consumer,
        sfn_snapshot,
    ):
        activity_name = f"activity-{short_uid()}"
        create_activity_output = create_activity(name=activity_name)
        activity_arn = create_activity_output["activityArn"]
        sfn_snapshot.add_transformer(RegexTransformer(activity_arn, "activity_arn"))
        sfn_snapshot.add_transformer(RegexTransformer(activity_name, "activity_name"))
        sfn_snapshot.match("create_activity_output", create_activity_output)

        sfn_activity_consumer(
            template=ActivityTemplate.load_sfn_template(
                ActivityTemplate.HEARTBEAT_ID_ACTIVITY_CONSUMER
            ),
            activity_arn=activity_arn,
        )

        template = ActivityTemplate.load_sfn_template(ActivityTemplate.BASE_ACTIVITY_TASK_HEARTBEAT)
        template["States"]["ActivityTask"]["Resource"] = activity_arn
        definition = json.dumps(template)

        exec_input = json.dumps({"Value1": "HelloWorld"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_activity_task_start_timeout(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_activity,
        sfn_activity_consumer,
        sfn_snapshot,
    ):
        activity_name = f"activity-{short_uid()}"
        create_activity_output = create_activity(name=activity_name)
        activity_arn = create_activity_output["activityArn"]
        sfn_snapshot.add_transformer(RegexTransformer(activity_arn, "activity_arn"))
        sfn_snapshot.add_transformer(RegexTransformer(activity_name, "activity_name"))
        sfn_snapshot.match("create_activity_output", create_activity_output)

        sfn_activity_consumer(
            template=ActivityTemplate.load_sfn_template(
                ActivityTemplate.BASE_ID_ACTIVITY_CONSUMER_TIMEOUT
            ),
            activity_arn=activity_arn,
        )

        template = ActivityTemplate.load_sfn_template(ActivityTemplate.BASE_ACTIVITY_TASK_TIMEOUT)
        template["States"]["ActivityTask"]["Resource"] = activity_arn
        definition = json.dumps(template)

        exec_input = json.dumps({"Value1": "HelloWorld"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
