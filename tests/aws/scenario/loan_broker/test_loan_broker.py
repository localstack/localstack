"""
This scenario test is taken from https://github.com/localstack-samples/sample-loan-broker-stepfunctions-lambda
which in turn is based on https://www.enterpriseintegrationpatterns.com/ramblings/loanbroker_stepfunctions.html
"""

import json
import os
from dataclasses import dataclass

import aws_cdk
import aws_cdk as cdk
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_lambda as awslambda
import aws_cdk.aws_logs as logs
import aws_cdk.aws_stepfunctions as sfn
import aws_cdk.aws_stepfunctions_tasks as tasks
import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import await_execution_terminated
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid

RECIPIENT_LIST_STACK_NAME = "LoanBroker-RecipientList"
PROJECT_NAME = "CDK Loan Broker"
OUTPUT_LOAN_BROKER_STATE_MACHINE_ARN = "LoanBrokerArn"
OUTPUT_LOAN_BROKER_LOG_GROUP_NAME = "LogGroupName"
OUTPUT_LOAN_BROKER_TABLE = "TableName"
LOAN_BROKER_TABLE = "LoanBrokerBanksTable"

CREDIT_BUREAU_JS = "./functions/bank_app_credit_bureau.js"
BANK_APP_JS = "./functions/bank_app.js"


def _read_file_as_string(filename: str) -> str:
    file_path = os.path.join(os.path.dirname(__file__), filename)
    return load_file(file_path)


@dataclass
class Bank:
    bank_id: str
    base_rate: str
    max_loan: str
    min_credit_score: str

    def get_env(self) -> dict:
        return {
            "BANK_ID": self.bank_id,
            "BASE_RATE": self.base_rate,
            "MAX_LOAN_AMOUNT": self.max_loan,
            "MIN_CREDIT_SCORE": self.min_credit_score,
        }


class TestLoanBrokerScenario:
    BANKS = {
        "BankRecipientPawnShop": Bank(
            bank_id="PawnShop", base_rate="5", max_loan="500000", min_credit_score="400"
        ),
        "BankRecipientUniversal": Bank(
            bank_id="Universal", base_rate="4", max_loan="700000", min_credit_score="500"
        ),
        "BankRecipientPremium": Bank(
            bank_id="Premium", base_rate="3", max_loan="900000", min_credit_score="600"
        ),
    }

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="LoanBroaker")
        recipient_stack = cdk.Stack(infra.cdk_app, RECIPIENT_LIST_STACK_NAME)
        cdk.Tags.of(recipient_stack).add("Project", PROJECT_NAME)
        cdk.Tags.of(recipient_stack).add("Stackname", RECIPIENT_LIST_STACK_NAME)
        self.setup_recipient_list_stack(recipient_stack)

        # set skip_teardown=True to prevent the stack to be deleted
        with infra.provisioner(skip_teardown=False) as prov:
            yield prov

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Table.DeletionProtectionEnabled",
            "$..Table.ProvisionedThroughput.LastDecreaseDateTime",
            "$..Table.ProvisionedThroughput.LastIncreaseDateTime",
            "$..Table.Replicas",
        ]
    )
    def test_prefill_dynamodb_table(self, aws_client, infrastructure, snapshot):
        """setups the dynamodb for the following tests,
        additionally tests some typical dynamodb APIs
        """
        outputs = infrastructure.get_stack_outputs(RECIPIENT_LIST_STACK_NAME)
        table_name = outputs.get(OUTPUT_LOAN_BROKER_TABLE)
        snapshot.add_transformer(snapshot.transform.dynamodb_api())

        describe_table = aws_client.dynamodb.describe_table(TableName=table_name)
        snapshot.match("describe_table", describe_table)

        result = aws_client.dynamodb.put_item(
            TableName=table_name,
            Item={"Type": {"S": "Home"}, "BankAddress": {"L": [{"S": "will be replaced"}]}},
        )
        snapshot.match("put_item", result)

        result = aws_client.dynamodb.put_item(
            TableName=table_name,
            Item={"Type": {"S": "Test"}, "Hello": {"S": "something"}},
        )
        snapshot.match("put_item_2", result)

        scan_result = aws_client.dynamodb.scan(TableName=table_name)

        # the order for scan is not guarnateed, but we want to compare it
        scan_result["Items"].sort(key=lambda x: x["Type"]["S"], reverse=True)
        snapshot.match("scan", scan_result)

        item = aws_client.dynamodb.get_item(TableName=table_name, Key={"Type": {"S": "Home"}})
        snapshot.match("get_item", item)

        bank_addresses = [{"S": bank_name} for bank_name in self.BANKS.keys()]

        # this entry will be required for the upcoming tests
        result = aws_client.dynamodb.update_item(
            TableName=table_name,
            Key={"Type": {"S": "Home"}},
            UpdateExpression="SET BankAddress=:v",
            ExpressionAttributeValues={":v": {"L": bank_addresses}},
        )
        snapshot.match("update_item", result)

        item = aws_client.dynamodb.get_item(TableName=table_name, Key={"Type": {"S": "Home"}})
        snapshot.match("get_item2", item)

        # delete item
        delete_item = aws_client.dynamodb.delete_item(
            TableName=table_name, Key={"Type": {"S": "Test"}}
        )
        snapshot.match("delete_item", delete_item)

        scan_result = aws_client.dynamodb.scan(TableName=table_name)
        snapshot.match("scan_2", scan_result)

        # TODO could further test dynamodb if required

    @pytest.mark.parametrize(
        "step_function_input,expected_result",
        [
            # score linked to this SSN will receive quotes
            ({"SSN": "123-45-6789", "Amount": 5000, "Term": 30}, "SUCCEEDED"),
            # score linked to this SSN will not receive quotes, but step function call succeeds
            ({"SSN": "458-45-6789", "Amount": 5000, "Term": 30}, "SUCCEEDED"),
            ({"SSN": "inv-45-6789", "Amount": 5000, "Term": 30}, "FAILED"),
            ({"unexpected": "234-45-6789"}, "FAILED"),
            pytest.param(
                {"SSN": "234-45-6789"},
                "FAILED",
                marks=pytest.mark.skipif(
                    condition=not is_aws_cloud(),
                    reason="stays in RUNNING on LS, but should be FAILED",
                ),
            ),  # FIXME
        ],
    )
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..traceHeader", "$..cause"]
    )  # TODO add missing properties
    def test_stepfunctions_input_recipient_list(
        self, aws_client, infrastructure, step_function_input, expected_result, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.stepfunctions_api())
        snapshot.add_transformer(snapshot.transform.key_value("executionArn"))
        snapshot.add_transformer(snapshot.transform.key_value("stateMachineArn"))
        snapshot.add_transformer(snapshot.transform.key_value("traceHeader"))
        snapshot.add_transformer(snapshot.transform.key_value("name"))

        outputs = infrastructure.get_stack_outputs(RECIPIENT_LIST_STACK_NAME)
        state_machine_arn = outputs.get(OUTPUT_LOAN_BROKER_STATE_MACHINE_ARN)
        execution_name = f"my-test-{short_uid()}"

        result = aws_client.stepfunctions.start_execution(
            name=execution_name,
            stateMachineArn=state_machine_arn,
            input=json.dumps(step_function_input),
        )
        execution_arn = result["executionArn"]

        await_execution_terminated(aws_client.stepfunctions, execution_arn)

        result = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)

        snapshot.match("describe-execution-finished", result)

        # TODO verify logs in LogGroup -> not working yet for LS

    def setup_recipient_list_stack(self, stack: cdk.Stack):
        # https://www.enterpriseintegrationpatterns.com/ramblings/loanbroker_stepfunctions_recipient_list.html
        credit_bureau_lambda = awslambda.Function(
            stack,
            "CreditBureauLambda",
            handler="index.handler",
            code=awslambda.InlineCode(code=_read_file_as_string(CREDIT_BUREAU_JS)),
            runtime=awslambda.Runtime.NODEJS_18_X,
        )

        get_credit_score_form_credit_bureau = tasks.LambdaInvoke(
            stack,
            "Get Credit Score from credit bureau",
            lambda_function=credit_bureau_lambda,
            payload=sfn.TaskInput.from_object({"SSN.$": "$.SSN", "RequestId.$": "$$.Execution.Id"}),
            result_path="$.Credit",
            result_selector={
                "Score.$": "$.Payload.body.score",
                "History.$": "$.Payload.body.history",
            },
            retry_on_service_exceptions=False,
        )

        bank_table = dynamodb.Table(
            stack,
            "LoanBrokerBanksTable",
            partition_key={"name": "Type", "type": dynamodb.AttributeType.STRING},
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            table_name=LOAN_BROKER_TABLE,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        fetch_bank_address_from_database = tasks.DynamoGetItem(
            stack,
            "Fetch Bank Addresses from database",
            table=bank_table,
            key={"Type": tasks.DynamoAttributeValue.from_string("Home")},
            result_path="$.Banks",
            result_selector={"BankAddress.$": "$.Item.BankAddress.L[*].S"},
        )

        get_individual_bank_quotes = sfn.CustomState(
            stack,
            "Get individual bank quotes",
            state_json={
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {
                    "FunctionName.$": "$.function",
                    "Payload": {
                        "SSN.$": "$.SSN",
                        "Amount.$": "$.Amount",
                        "Term.$": "$.Term",
                        "Credit.$": "$.Credit",
                    },
                },
                "ResultSelector": {"Quote.$": "$.Payload"},
            },
        )

        get_all_bank_quotes = sfn.Map(
            stack,
            "Get all bank quotes",
            items_path="$.Banks.BankAddress",
            parameters={
                "function.$": "$$.Map.Item.Value",
                "SSN.$": "$.SSN",
                "Amount.$": "$.Amount",
                "Term.$": "$.Term",
                "Credit.$": "$.Credit",
            },
            result_path="$.Quotes",
        )

        loan_broker_definition = get_credit_score_form_credit_bureau.next(
            fetch_bank_address_from_database
        ).next(get_all_bank_quotes.iterator(get_individual_bank_quotes))

        loan_broker_log_group = logs.LogGroup(
            stack, "LoanBrokerLogGroup", removal_policy=aws_cdk.RemovalPolicy.DESTROY
        )
        loan_broker = sfn.StateMachine(
            stack,
            "LoanBroker",
            definition=loan_broker_definition,
            state_machine_type=sfn.StateMachineType.STANDARD,
            timeout=cdk.Duration.minutes(5),
            logs={
                "destination": loan_broker_log_group,
                "level": sfn.LogLevel.ALL,
                "include_execution_data": True,
            },
            tracing_enabled=True,
        )

        for bank_name, bank_env in self.BANKS.items():
            bank_function = awslambda.Function(
                stack,
                bank_name,
                runtime=awslambda.Runtime.NODEJS_18_X,
                handler="index.handler",
                code=awslambda.InlineCode(code=_read_file_as_string(BANK_APP_JS)),
                function_name=bank_name,
                environment=bank_env.get_env(),
            )

            bank_function.grant_invoke(loan_broker)

        cdk.CfnOutput(
            stack, OUTPUT_LOAN_BROKER_STATE_MACHINE_ARN, value=loan_broker.state_machine_arn
        )

        cdk.CfnOutput(
            stack, OUTPUT_LOAN_BROKER_LOG_GROUP_NAME, value=loan_broker_log_group.log_group_name
        )

        cdk.CfnOutput(stack, OUTPUT_LOAN_BROKER_TABLE, value=bank_table.table_name)
