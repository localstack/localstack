import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@markers.snapshot.skip_snapshot_verify(paths=["$..encryptionConfiguration"])
class TestSnfApiActivities:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "activity_base_name",
        [
            "Activity1",
            "activity-name_123",
            "ACTIVITY_NAME_ABC",
            "activity.name",
            "activity.name.v2",
            "activityName.with.dots",
            "activity-name.1",
            "activity_123.name",
            "a" * 71,  # this plus the uuid postfix is a name of length 80
        ],
    )
    def test_create_describe_delete_activity(
        self,
        create_activity,
        sfn_snapshot,
        aws_client,
        activity_base_name,
    ):
        activity_name = f"{activity_base_name}-{short_uid()}"
        create_activity_response = aws_client.stepfunctions.create_activity(name=activity_name)
        activity_arn = create_activity_response["activityArn"]
        sfn_snapshot.add_transformer(RegexTransformer(activity_arn, "activity_arn"))
        sfn_snapshot.add_transformer(RegexTransformer(activity_name, "activity_name"))
        sfn_snapshot.match("create_activity_response", create_activity_response)

        create_activity_response_duplicate = aws_client.stepfunctions.create_activity(
            name=activity_name
        )
        sfn_snapshot.match("create_activity_response_duplicate", create_activity_response_duplicate)

        describe_activity_response = aws_client.stepfunctions.describe_activity(
            activityArn=activity_arn
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..creationDate", replacement="creation-date", replace_reference=False
            )
        )
        sfn_snapshot.match("describe_activity_response", describe_activity_response)

        delete_activity_response = aws_client.stepfunctions.delete_activity(
            activityArn=activity_arn
        )
        sfn_snapshot.match("delete_activity_response", delete_activity_response)

        delete_activity_response_2 = aws_client.stepfunctions.delete_activity(
            activityArn=activity_arn
        )
        sfn_snapshot.match("delete_activity_response_2", delete_activity_response_2)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "activity_name",
        [
            "activity name",
            "activity<name",
            "activity>name",
            "activity{name",
            "activity}name",
            "activity[name",
            "activity]name",
            "activity?name",
            "activity*name",
            'activity"name',
            "activity#name",
            "activity%name",
            "activity\\name",
            "activity^name",
            "activity|name",
            "activity~name",
            "activity`name",
            "activity$name",
            "activity&name",
            "activity,name",
            "activity;name",
            "activity:name",
            "activity/name",
            chr(0) + "activity",
            "activity" + chr(31),
            "activity" + chr(127),
        ],
    )
    def test_create_activity_invalid_name(
        self, create_activity, sfn_snapshot, aws_client_no_retry, activity_name
    ):
        with pytest.raises(ClientError) as e:
            aws_client_no_retry.stepfunctions.create_activity(name=activity_name)
        sfn_snapshot.match("invalid_name", e.value.response)

    @markers.aws.validated
    def test_describe_deleted_activity(
        self, create_activity, sfn_snapshot, aws_client, aws_client_no_retry
    ):
        create_activity_response = aws_client.stepfunctions.create_activity(
            name=f"TestActivity-{short_uid()}"
        )
        activity_arn = create_activity_response["activityArn"]
        sfn_snapshot.add_transformer(RegexTransformer(activity_arn, "activity_arn"))
        aws_client.stepfunctions.delete_activity(activityArn=activity_arn)
        with pytest.raises(ClientError) as e:
            aws_client_no_retry.stepfunctions.describe_activity(activityArn=activity_arn)
        sfn_snapshot.match("no_such_activity", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..exception_value"])
    def test_describe_activity_invalid_arn(
        self,
        sfn_snapshot,
        aws_client_no_retry,
    ):
        with pytest.raises(ClientError) as exc:
            aws_client_no_retry.stepfunctions.describe_activity(activityArn="no_an_activity_arn")
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    def test_get_activity_task_deleted(
        self, create_activity, sfn_snapshot, aws_client, aws_client_no_retry
    ):
        create_activity_response = aws_client.stepfunctions.create_activity(
            name=f"TestActivity-{short_uid()}"
        )
        activity_arn = create_activity_response["activityArn"]
        sfn_snapshot.add_transformer(RegexTransformer(activity_arn, "activity_arn"))
        aws_client.stepfunctions.delete_activity(activityArn=activity_arn)
        with pytest.raises(ClientError) as e:
            aws_client_no_retry.stepfunctions.get_activity_task(activityArn=activity_arn)
        sfn_snapshot.match("no_such_activity", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..exception_value"])
    def test_get_activity_task_invalid_arn(
        self,
        sfn_snapshot,
        aws_client_no_retry,
    ):
        with pytest.raises(ClientError) as exc:
            aws_client_no_retry.stepfunctions.get_activity_task(activityArn="no_an_activity_arn")
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    def test_list_activities(
        self,
        create_activity,
        sfn_snapshot,
        aws_client,
    ):
        activity_arns = set()
        for i in range(3):
            activity_name = f"TestActivity-{i}-{short_uid()}"
            create_activity_response = aws_client.stepfunctions.create_activity(name=activity_name)
            activity_arn = create_activity_response["activityArn"]
            sfn_snapshot.add_transformer(RegexTransformer(activity_arn, f"activity_arn_{i}"))
            sfn_snapshot.add_transformer(RegexTransformer(activity_name, f"activity_name_{i}"))
            activity_arns.add(activity_arn)

        list_activities_response = aws_client.stepfunctions.list_activities()
        activities = list_activities_response["activities"]
        activities = list(
            filter(lambda activity: activity["activityArn"] in activity_arns, activities)
        )
        list_activities_response["activities"] = activities

        sfn_snapshot.match("list_activities_response", list_activities_response)
