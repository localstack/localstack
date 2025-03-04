import json
import time

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.stepfunctions import Arn, RoutingConfigurationListItem
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    await_execution_terminated,
    await_state_machine_alias_is_created,
    await_state_machine_alias_is_deleted,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
        "$..redriveCount",
        "$..redriveStatus",
        "$..redriveStatusReason",
    ]
)
class TestSfnApiAliasing:
    @markers.aws.validated
    def test_base_create_alias_single_router_config(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=definition_str,
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )

        state_machine_version_arn = create_state_machine_response["stateMachineVersionArn"]
        state_machine_alias_name = f"AliasName-{short_uid()}"
        sfn_snapshot.add_transformer(
            RegexTransformer(state_machine_alias_name, "state_machine_alias_name")
        )

        create_state_machine_alias_response = create_state_machine_alias(
            target_aws_client=aws_client,
            description="create state machine alias description",
            name=state_machine_alias_name,
            routingConfiguration=[
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arn, weight=100
                )
            ],
        )
        sfn_snapshot.match(
            "create_state_machine_alias_response", create_state_machine_alias_response
        )

    @markers.aws.validated
    def test_error_create_alias_with_state_machine_arn(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=definition_str,
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                description="create state machine alias description",
                name=f"AliasName-{short_uid()}",
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_arn, weight=100
                    )
                ],
            )
        sfn_snapshot.match(
            "exception", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

    @markers.aws.validated
    def test_error_create_alias_not_idempotent(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        state_machine_name = f"state_machine_{short_uid()}"

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=json.dumps(definition),
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]
        state_machine_version_arn_v0 = create_state_machine_response["stateMachineVersionArn"]

        definition["Comment"] = "Definition v1"
        update_state_machine_response = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=json.dumps(definition), publish=True
        )
        state_machine_version_arn_v1 = update_state_machine_response["stateMachineVersionArn"]

        state_machine_alias_name = f"AliasName-{short_uid()}"
        state_machine_alias_description = "create state machine alias description"
        state_machine_alias_routing_configuration = [
            RoutingConfigurationListItem(
                stateMachineVersionArn=state_machine_version_arn_v0, weight=100
            )
        ]
        sfn_snapshot.add_transformer(
            RegexTransformer(state_machine_alias_name, "state_machine_alias_name")
        )
        create_state_machine_alias_response = create_state_machine_alias(
            target_aws_client=aws_client,
            description=state_machine_alias_description,
            name=state_machine_alias_name,
            routingConfiguration=state_machine_alias_routing_configuration,
        )
        sfn_snapshot.match(
            "create_state_machine_alias_response", create_state_machine_alias_response
        )

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                description="This is a different description",
                name=state_machine_alias_name,
                routingConfiguration=state_machine_alias_routing_configuration,
            )
        sfn_snapshot.match(
            "not_idempotent_description",
            {"exception_typename": exc.typename, "exception_value": exc.value},
        )

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                description=state_machine_alias_description,
                name=state_machine_alias_name,
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arn_v0, weight=50
                    ),
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arn_v1, weight=50
                    ),
                ],
            )
        sfn_snapshot.match(
            "not_idempotent_routing_configuration",
            {"exception_typename": exc.typename, "exception_value": exc.value},
        )

    @markers.aws.validated
    def test_idempotent_create_alias(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=definition_str,
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )

        state_machine_arn = create_state_machine_response["stateMachineArn"]
        state_machine_version_arn = create_state_machine_response["stateMachineVersionArn"]
        state_machine_alias_name = f"AliasName-{short_uid()}"
        sfn_snapshot.add_transformer(
            RegexTransformer(state_machine_alias_name, "state_machine_alias_name")
        )

        for attempt_number in range(2):
            create_state_machine_alias_response = create_state_machine_alias(
                target_aws_client=aws_client,
                description="create state machine alias description",
                name=state_machine_alias_name,
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arn, weight=100
                    )
                ],
            )
            sfn_snapshot.match(
                f"create_state_machine_alias_response_attempt_{attempt_number}",
                create_state_machine_alias_response,
            )

        create_state_machine_alias_response = create_state_machine_alias(
            target_aws_client=aws_client,
            description="create state machine alias description",
            name=f"{state_machine_alias_name}-second",
            routingConfiguration=[
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arn, weight=100
                )
            ],
        )
        sfn_snapshot.match(
            "create_state_machine_alias_response_different_name",
            create_state_machine_alias_response,
        )

        list_state_machine_aliases_response = aws_client.stepfunctions.list_state_machine_aliases(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match(
            "list_state_machine_aliases_response", list_state_machine_aliases_response
        )

    @markers.aws.validated
    def test_error_create_alias_invalid_router_configs(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_client = aws_client.stepfunctions

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=json.dumps(definition),
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        state_machine_version_arns: list[Arn] = list()
        state_machine_version_arns.append(create_state_machine_response["stateMachineVersionArn"])
        for version_number in range(2):
            definition["Comment"] = f"Definition for version {version_number}"
            update_state_machine_response = sfn_client.update_state_machine(
                stateMachineArn=state_machine_arn, definition=json.dumps(definition), publish=True
            )
            state_machine_version_arn = update_state_machine_response["stateMachineVersionArn"]
            state_machine_version_arns.append(state_machine_version_arn)

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                name=f"AliasName-{short_uid()}",
                routingConfiguration=[],
            )
        sfn_snapshot.match(
            "no_routing", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                name=f"AliasName-{short_uid()}",
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[0], weight=50
                    ),
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[1], weight=30
                    ),
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[2], weight=20
                    ),
                ],
            )
        sfn_snapshot.match(
            "too_many_routing", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                name=f"AliasName-{short_uid()}",
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[0], weight=50
                    ),
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[0], weight=50
                    ),
                ],
            )
        sfn_snapshot.match(
            "duplicate_routing", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                name=f"AliasName-{short_uid()}",
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_arn, weight=70
                    ),
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[1], weight=30
                    ),
                ],
            )
        sfn_snapshot.match(
            "invalid_arn", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                name=f"AliasName-{short_uid()}",
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[0], weight=101
                    )
                ],
            )
        sfn_snapshot.match(
            "weight_too_large", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                name=f"AliasName-{short_uid()}",
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[0], weight=-1
                    )
                ],
            )
        sfn_snapshot.match(
            "weight_too_small", {"exception_typename": exc.typename, "exception_value": exc.value}
        )

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                name=f"AliasName-{short_uid()}",
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[0], weight=70
                    ),
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[1], weight=29
                    ),
                ],
            )
        sfn_snapshot.match(
            "sum_weights_less_than_100",
            {"exception_typename": exc.typename, "exception_value": exc.value},
        )

        with pytest.raises(Exception) as exc:
            create_state_machine_alias(
                target_aws_client=aws_client,
                name=f"AliasName-{short_uid()}",
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[0], weight=70
                    ),
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arns[1], weight=31
                    ),
                ],
            )
        sfn_snapshot.match(
            "sum_weights_more_than_100",
            {"exception_typename": exc.typename, "exception_value": exc.value},
        )

    @markers.aws.validated
    def test_error_create_alias_invalid_name(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=definition_str,
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )
        state_machine_version_arn = create_state_machine_response["stateMachineVersionArn"]

        invalid_names = ["123", "", "A" * 81, "INVALID ALIAS", "!INVALID", "ALIAS@"]
        for invalid_name in invalid_names:
            with pytest.raises(Exception) as exc:
                create_state_machine_alias(
                    target_aws_client=aws_client,
                    description="create state machine alias description",
                    name=invalid_name,
                    routingConfiguration=[
                        RoutingConfigurationListItem(
                            stateMachineVersionArn=state_machine_version_arn, weight=100
                        )
                    ],
                )
            sfn_snapshot.match(
                f"exception_for_name{invalid_name}",
                {"exception_typename": exc.typename, "exception_value": exc.value},
            )

    @markers.aws.validated
    def test_base_lifecycle_create_delete_list(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_client = aws_client.stepfunctions

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=definition_str,
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )

        state_machine_arn = create_state_machine_response["stateMachineArn"]
        state_machine_version_arn = create_state_machine_response["stateMachineVersionArn"]

        list_state_machine_aliases_response = sfn_client.list_state_machine_aliases(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match(
            "list_state_machine_aliases_response_empty", list_state_machine_aliases_response
        )

        state_machine_alias_base_name = f"AliasName-{short_uid()}"
        sfn_snapshot.add_transformer(
            RegexTransformer(state_machine_alias_base_name, "state_machine_alias_base_name")
        )
        state_machine_alias_arns: list[str] = list()
        for num in range(3):
            state_machine_alias_name = f"{state_machine_alias_base_name}-{num}"
            create_state_machine_alias_response = create_state_machine_alias(
                target_aws_client=aws_client,
                description="create state machine alias description",
                name=state_machine_alias_name,
                routingConfiguration=[
                    RoutingConfigurationListItem(
                        stateMachineVersionArn=state_machine_version_arn, weight=100
                    )
                ],
            )
            sfn_snapshot.match(
                f"create_state_machine_alias_response_num_{num}",
                create_state_machine_alias_response,
            )
            state_machine_alias_arn = create_state_machine_alias_response["stateMachineAliasArn"]
            state_machine_alias_arns.append(state_machine_alias_arn)

            await_state_machine_alias_is_created(
                stepfunctions_client=sfn_client,
                state_machine_arn=state_machine_arn,
                state_machine_alias_arn=state_machine_alias_arn,
            )

            list_state_machine_aliases_response = sfn_client.list_state_machine_aliases(
                stateMachineArn=state_machine_arn
            )
            sfn_snapshot.match(
                f"list_state_machine_aliases_response_after_creation_{num}",
                list_state_machine_aliases_response,
            )

        for num, state_machine_alias_arn in enumerate(state_machine_alias_arns):
            delete_state_machine_alias_response = sfn_client.delete_state_machine_alias(
                stateMachineAliasArn=state_machine_alias_arn
            )
            sfn_snapshot.match(
                f"delete_state_machine_alias_response_{num}",
                delete_state_machine_alias_response,
            )

            await_state_machine_alias_is_deleted(
                stepfunctions_client=sfn_client,
                state_machine_arn=state_machine_arn,
                state_machine_alias_arn=state_machine_alias_arn,
            )

            list_state_machine_aliases_response = sfn_client.list_state_machine_aliases(
                stateMachineArn=state_machine_arn
            )
            sfn_snapshot.match(
                f"list_state_machine_aliases_response_after_deletion_{num}",
                list_state_machine_aliases_response,
            )

    @markers.aws.validated
    def test_update_no_such_alias_arn(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_client = aws_client.stepfunctions

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=json.dumps(definition),
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]
        state_machine_version_arn = create_state_machine_response["stateMachineVersionArn"]

        state_machine_alias_name = f"AliasName-{short_uid()}"
        sfn_snapshot.add_transformer(
            RegexTransformer(state_machine_alias_name, "state_machine_alias_name")
        )

        create_state_machine_alias_response = create_state_machine_alias(
            target_aws_client=aws_client,
            description="create state machine alias description",
            name=state_machine_alias_name,
            routingConfiguration=[
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arn, weight=100
                )
            ],
        )
        sfn_snapshot.match(
            "create_state_machine_alias_response", create_state_machine_alias_response
        )
        state_machine_alias_arn = create_state_machine_alias_response["stateMachineAliasArn"]
        await_state_machine_alias_is_created(
            stepfunctions_client=sfn_client,
            state_machine_arn=state_machine_arn,
            state_machine_alias_arn=state_machine_alias_arn,
        )

        sfn_client.delete_state_machine_alias(stateMachineAliasArn=state_machine_alias_arn)
        await_state_machine_alias_is_deleted(
            stepfunctions_client=sfn_client,
            state_machine_arn=state_machine_arn,
            state_machine_alias_arn=state_machine_alias_arn,
        )

        with pytest.raises(Exception) as exc:
            sfn_client.update_state_machine_alias(
                stateMachineAliasArn=state_machine_alias_arn,
                description="Updated state machine alias description",
            )
        sfn_snapshot.match(
            "update_no_such_alias_arn",
            {"exception_typename": exc.typename, "exception_value": exc.value},
        )

    @markers.aws.validated
    def test_base_lifecycle_create_invoke_describe_list(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_client = aws_client.stepfunctions

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=definition_str,
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )

        state_machine_arn = create_state_machine_response["stateMachineArn"]
        state_machine_version_arn = create_state_machine_response["stateMachineVersionArn"]

        list_state_machine_aliases_response = sfn_client.list_state_machine_aliases(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match(
            "list_state_machine_aliases_response_empty", list_state_machine_aliases_response
        )

        state_machine_alias_name = f"AliasName-{short_uid()}"
        sfn_snapshot.add_transformer(
            RegexTransformer(state_machine_alias_name, "state_machine_alias_name")
        )

        create_state_machine_alias_response = create_state_machine_alias(
            target_aws_client=aws_client,
            description="create state machine alias description",
            name=state_machine_alias_name,
            routingConfiguration=[
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arn, weight=100
                )
            ],
        )
        sfn_snapshot.match(
            "create_state_machine_alias_response", create_state_machine_alias_response
        )
        state_machine_alias_arn = create_state_machine_alias_response["stateMachineAliasArn"]

        await_state_machine_alias_is_created(
            stepfunctions_client=sfn_client,
            state_machine_arn=state_machine_arn,
            state_machine_alias_arn=state_machine_alias_arn,
        )

        start_execution_response = sfn_client.start_execution(
            stateMachineArn=state_machine_alias_arn, input="{}"
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_exec_arn(start_execution_response, 0)
        )
        execution_arn = start_execution_response["executionArn"]
        sfn_snapshot.match("start_execution_response_through_alias", start_execution_response)

        await_execution_terminated(stepfunctions_client=sfn_client, execution_arn=execution_arn)

        describe_execution_response = sfn_client.describe_execution(executionArn=execution_arn)
        sfn_snapshot.match("describe_execution_response_through_alias", describe_execution_response)

        start_execution_response = sfn_client.start_execution(
            stateMachineArn=state_machine_version_arn, input="{}"
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_exec_arn(start_execution_response, 1)
        )
        execution_arn = start_execution_response["executionArn"]
        sfn_snapshot.match("start_execution_response_through_version_arn", start_execution_response)

        await_execution_terminated(stepfunctions_client=sfn_client, execution_arn=execution_arn)

        describe_execution_response = sfn_client.describe_execution(executionArn=execution_arn)
        sfn_snapshot.match(
            "describe_execution_response_through_version_arn", describe_execution_response
        )

        list_executions_response = sfn_client.list_executions(stateMachineArn=state_machine_arn)
        sfn_snapshot.match("list_executions_response", list_executions_response)

    @markers.aws.validated
    def test_base_lifecycle_create_update_describe(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_client = aws_client.stepfunctions

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=json.dumps(definition),
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]

        state_machine_version_arns: list[Arn] = list()
        state_machine_version_arns.append(create_state_machine_response["stateMachineVersionArn"])
        for version_number in range(2):
            definition["Comment"] = f"Definition for version {version_number}"
            update_state_machine_response = sfn_client.update_state_machine(
                stateMachineArn=state_machine_arn, definition=json.dumps(definition), publish=True
            )
            state_machine_version_arn = update_state_machine_response["stateMachineVersionArn"]
            state_machine_version_arns.append(state_machine_version_arn)

        state_machine_alias_name = f"AliasName-{short_uid()}"
        sfn_snapshot.add_transformer(
            RegexTransformer(state_machine_alias_name, "state_machine_alias_name")
        )

        create_state_machine_alias_response = create_state_machine_alias(
            target_aws_client=aws_client,
            description="create state machine alias description",
            name=state_machine_alias_name,
            routingConfiguration=[
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arns[0], weight=100
                )
            ],
        )
        sfn_snapshot.match(
            "create_state_machine_alias_response", create_state_machine_alias_response
        )
        state_machine_alias_arn = create_state_machine_alias_response["stateMachineAliasArn"]

        update_state_machine_alias_response = sfn_client.update_state_machine_alias(
            stateMachineAliasArn=state_machine_alias_arn,
            description="new description",
        )
        sfn_snapshot.match(
            "update_state_machine_alias_description_response", update_state_machine_alias_response
        )
        if is_aws_cloud():
            time.sleep(30)
        describe_state_machine_alias_response = sfn_client.describe_state_machine_alias(
            stateMachineAliasArn=state_machine_alias_arn
        )
        sfn_snapshot.match(
            "describe_state_machine_alias_update_description_response",
            describe_state_machine_alias_response,
        )

        update_state_machine_alias_response = sfn_client.update_state_machine_alias(
            stateMachineAliasArn=state_machine_alias_arn,
            routingConfiguration=[
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arns[0], weight=50
                ),
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arns[1], weight=50
                ),
            ],
        )
        sfn_snapshot.match(
            "update_state_machine_alias_routing_configuration_response",
            update_state_machine_alias_response,
        )
        if is_aws_cloud():
            time.sleep(30)
        describe_state_machine_alias_response = sfn_client.describe_state_machine_alias(
            stateMachineAliasArn=state_machine_alias_arn
        )
        sfn_snapshot.match(
            "describe_state_machine_alias_update_routing_configuration_response",
            describe_state_machine_alias_response,
        )

    @markers.aws.validated
    def test_delete_version_with_alias(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_client = aws_client.stepfunctions

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=json.dumps(definition),
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]
        state_machine_version_arn = create_state_machine_response["stateMachineVersionArn"]

        state_machine_alias_name = f"AliasName-{short_uid()}"
        sfn_snapshot.add_transformer(
            RegexTransformer(state_machine_alias_name, "state_machine_alias_name")
        )

        create_state_machine_alias_response = create_state_machine_alias(
            target_aws_client=aws_client,
            description="create state machine alias description",
            name=state_machine_alias_name,
            routingConfiguration=[
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arn, weight=100
                )
            ],
        )
        sfn_snapshot.match(
            "create_state_machine_alias_response", create_state_machine_alias_response
        )
        state_machine_alias_arn = create_state_machine_alias_response["stateMachineAliasArn"]
        await_state_machine_alias_is_created(
            stepfunctions_client=sfn_client,
            state_machine_arn=state_machine_arn,
            state_machine_alias_arn=state_machine_alias_arn,
        )

        with pytest.raises(Exception) as exc:
            sfn_client.delete_state_machine_version(
                stateMachineVersionArn=state_machine_version_arn
            )
        sfn_snapshot.match(
            "exception_delete_version_with_alias_reference",
            {"exception_typename": exc.typename, "exception_value": exc.value},
        )

        definition["Comment"] = "Definition v1"
        update_state_machine_response = aws_client.stepfunctions.update_state_machine(
            stateMachineArn=state_machine_arn, definition=json.dumps(definition), publish=True
        )
        state_machine_version_arn_v1 = update_state_machine_response["stateMachineVersionArn"]

        sfn_client.update_state_machine_alias(
            stateMachineAliasArn=state_machine_alias_arn,
            routingConfiguration=[
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arn_v1, weight=100
                )
            ],
        )
        if is_aws_cloud():
            time.sleep(30)
        describe_state_machine_alias_response = sfn_client.describe_state_machine_alias(
            stateMachineAliasArn=state_machine_alias_arn
        )
        sfn_snapshot.match(
            "describe_state_machine_alias_response", describe_state_machine_alias_response
        )

        delete_version_response = sfn_client.delete_state_machine_version(
            stateMachineVersionArn=state_machine_version_arn
        )
        sfn_snapshot.match("delete_version_response", delete_version_response)

    @markers.aws.validated
    def test_delete_revision_with_alias(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_client = aws_client.stepfunctions

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=json.dumps(definition),
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]
        state_machine_version_arn = create_state_machine_response["stateMachineVersionArn"]

        state_machine_alias_name = f"AliasName-{short_uid()}"
        sfn_snapshot.add_transformer(
            RegexTransformer(state_machine_alias_name, "state_machine_alias_name")
        )

        create_state_machine_alias_response = create_state_machine_alias(
            target_aws_client=aws_client,
            description="create state machine alias description",
            name=state_machine_alias_name,
            routingConfiguration=[
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arn, weight=100
                )
            ],
        )
        sfn_snapshot.match(
            "create_state_machine_alias_response", create_state_machine_alias_response
        )
        state_machine_alias_arn = create_state_machine_alias_response["stateMachineAliasArn"]
        await_state_machine_alias_is_created(
            stepfunctions_client=sfn_client,
            state_machine_arn=state_machine_arn,
            state_machine_alias_arn=state_machine_alias_arn,
        )

        delete_state_machine_response = sfn_client.delete_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("delete_state_machine_response", delete_state_machine_response)

    @markers.aws.validated
    def test_delete_no_such_alias_arn(
        self,
        create_state_machine_iam_role,
        create_state_machine,
        create_state_machine_alias,
        sfn_snapshot,
        aws_client,
    ):
        sfn_client = aws_client.stepfunctions

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        sfn_snapshot.add_transformer(RegexTransformer(sfn_role_arn, "sfn_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)

        state_machine_name = f"state_machine_{short_uid()}"
        create_state_machine_response = create_state_machine(
            target_aws_client=aws_client,
            name=state_machine_name,
            definition=json.dumps(definition),
            roleArn=sfn_role_arn,
            publish=True,
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.sfn_sm_create_arn(create_state_machine_response, 0)
        )
        state_machine_arn = create_state_machine_response["stateMachineArn"]
        state_machine_version_arn = create_state_machine_response["stateMachineVersionArn"]

        state_machine_alias_name = f"AliasName-{short_uid()}"
        sfn_snapshot.add_transformer(
            RegexTransformer(state_machine_alias_name, "state_machine_alias_name")
        )

        create_state_machine_alias_response = create_state_machine_alias(
            target_aws_client=aws_client,
            description="create state machine alias description",
            name=state_machine_alias_name,
            routingConfiguration=[
                RoutingConfigurationListItem(
                    stateMachineVersionArn=state_machine_version_arn, weight=100
                )
            ],
        )
        sfn_snapshot.match(
            "create_state_machine_alias_response", create_state_machine_alias_response
        )
        state_machine_alias_arn = create_state_machine_alias_response["stateMachineAliasArn"]
        await_state_machine_alias_is_created(
            stepfunctions_client=sfn_client,
            state_machine_arn=state_machine_arn,
            state_machine_alias_arn=state_machine_alias_arn,
        )

        sfn_client.delete_state_machine_alias(stateMachineAliasArn=state_machine_alias_arn)
        await_state_machine_alias_is_deleted(
            stepfunctions_client=sfn_client,
            state_machine_arn=state_machine_arn,
            state_machine_alias_arn=state_machine_alias_arn,
        )

        delete_state_machine_alias_response = sfn_client.delete_state_machine_alias(
            stateMachineAliasArn=state_machine_alias_arn
        )
        sfn_snapshot.match(
            "delete_state_machine_alias_response", delete_state_machine_alias_response
        )
