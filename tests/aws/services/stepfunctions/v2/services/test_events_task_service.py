import json

import pytest
from localstack_snapshot.snapshots import RegexTransformer

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.utils import create_and_record_execution, record_sqs_events


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..loggingConfiguration",
        "$..tracingConfiguration",
        # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestTaskServiceEvents:
    @markers.aws.validated
    def test_put_events_base(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        events_to_sqs_queue,
        aws_client,
        sfn_snapshot,
    ):
        detail_type = f"detail_type_{short_uid()}"
        event_pattern = {"detail-type": [detail_type]}
        queue_url = events_to_sqs_queue(event_pattern)
        sfn_snapshot.add_transformer(RegexTransformer(detail_type, "<detail-type>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))

        template = ST.load_sfn_template(ST.EVENTS_PUT_EVENTS)
        definition = json.dumps(template)

        entries = [
            {
                "Detail": json.dumps({"Message": "HelloWorld0"}),
                "DetailType": detail_type,
                "Source": "some.source",
            },
            {
                "Detail": {"Message": "HelloWorld1"},
                "DetailType": detail_type,
                "Source": "some.source",
            },
            {
                "Detail": {"Message": "HelloWorld2"},
                "DetailType": detail_type,
                "Source": "some.source",
                "Resources": [queue_url],
            },
        ]
        exec_input = json.dumps({"Entries": entries})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
        record_sqs_events(aws_client, queue_url, sfn_snapshot, len(entries))

    @pytest.mark.skip(
        reason="LS EventsBridge does not recognise the incorrect formation of the detail field"
    )
    @markers.aws.validated
    def test_put_events_malformed_detail(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        events_to_sqs_queue,
        aws_client,
        sfn_snapshot,
    ):
        detail_type = f"detail_type_{short_uid()}"
        event_pattern = {"detail-type": [detail_type]}
        queue_url = events_to_sqs_queue(event_pattern)
        sfn_snapshot.add_transformer(RegexTransformer(detail_type, "<detail-type>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))

        template = ST.load_sfn_template(ST.EVENTS_PUT_EVENTS)
        definition = json.dumps(template)

        entries = [
            {
                "Detail": json.dumps("jsonstring"),
                "DetailType": detail_type,
                "Source": "some.source",
            }
        ]
        exec_input = json.dumps({"Entries": entries})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
        record_sqs_events(aws_client, queue_url, sfn_snapshot, len(entries))

    @pytest.mark.skip(
        reason="LS EventsBridge does not update the FailedEntryCount object as expected."
    )
    @markers.aws.validated
    def test_put_events_no_source(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        events_to_sqs_queue,
        aws_client,
        sfn_snapshot,
    ):
        detail_type = f"detail_type_{short_uid()}"
        event_pattern = {"detail-type": [detail_type]}
        queue_url = events_to_sqs_queue(event_pattern)
        sfn_snapshot.add_transformer(RegexTransformer(detail_type, "<detail-type>"))
        sfn_snapshot.add_transformer(RegexTransformer(queue_url, "<sqs_queue_url>"))

        template = ST.load_sfn_template(ST.EVENTS_PUT_EVENTS)
        definition = json.dumps(template)

        entries = [
            {
                "Detail": {"Message": "HelloWorld1"},
                "DetailType": detail_type,
                "Source": "some.source",
            },
            {
                "Detail": {"Message": "HelloWorld"},
                "DetailType": detail_type,
            },
        ]
        exec_input = json.dumps({"Entries": entries})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
        record_sqs_events(aws_client, queue_url, sfn_snapshot, len(entries))
