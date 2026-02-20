import json
import re
from typing import Any

from localstack.aws.api.iam import MalformedPolicyDocumentException
from localstack.utils.aws.arns import PARTITION_NAMES

VALID_TOP_ELEMENTS = ["Version", "Id", "Statement", "Conditions"]

VALID_VERSIONS = ["2008-10-17", "2012-10-17"]

VALID_STATEMENT_ELEMENTS = [
    "Sid",
    "Action",
    "NotAction",
    "Resource",
    "NotResource",
    "Effect",
    "Principal",
    "NotPrincipal",
    "Condition",
]

VALID_EFFECTS = ["Allow", "Deny"]

VALID_CONDITIONS = [
    "StringEquals",
    "StringNotEquals",
    "StringEqualsIgnoreCase",
    "StringNotEqualsIgnoreCase",
    "StringLike",
    "StringNotLike",
    "NumericEquals",
    "NumericNotEquals",
    "NumericLessThan",
    "NumericLessThanEquals",
    "NumericGreaterThan",
    "NumericGreaterThanEquals",
    "DateEquals",
    "DateNotEquals",
    "DateLessThan",
    "DateLessThanEquals",
    "DateGreaterThan",
    "DateGreaterThanEquals",
    "Bool",
    "BinaryEquals",
    "IpAddress",
    "NotIpAddress",
    "ArnEquals",
    "ArnLike",
    "ArnNotEquals",
    "ArnNotLike",
    "Null",
]

VALID_CONDITION_PREFIXES = ["ForAnyValue:", "ForAllValues:"]

VALID_CONDITION_POSTFIXES = ["IfExists"]

SERVICE_TYPE_REGION_INFORMATION_ERROR_ASSOCIATIONS: dict[str, Any] = {
    "iam": {"error_message": "IAM resource {resource} cannot contain region information."},
    "s3": {
        "error_message": "Resource {resource} can not contain region information.",
        "valid_starting_values": ["accesspoint/"],
    },
}


VALID_RESOURCE_PATH_STARTING_VALUES: dict[str, Any] = {
    "iam": {
        "values": [
            "user/",
            "federated-user/",
            "role/",
            "group/",
            "instance-profile/",
            "mfa/",
            "server-certificate/",
            "policy/",
            "sms-mfa/",
            "saml-provider/",
            "oidc-provider/",
            "report/",
            "access-report/",
        ],
        "error_message": 'IAM resource path must either be "*", root, or start with {values}.',
    }
}


class BaseIAMPolicyValidator:
    def __init__(self, policy_document: str):
        self._policy_document = policy_document
        self._policy_json: dict[str, Any] = {}
        self._statements: list[dict[str, Any]] = []
        self._resource_error = (
            ""  # the first resource error found that does not generate a legacy parsing error
        )

    def validate(self) -> None:
        try:
            self._validate_syntax()
        except Exception:
            raise MalformedPolicyDocumentException("Syntax errors in policy.")
        try:
            self._validate_version()
        except Exception:
            raise MalformedPolicyDocumentException(
                "Policy document must be version 2012-10-17 or greater."
            )
        try:
            self._perform_first_legacy_parsing()
            self._validate_resources_for_formats()
            self._validate_not_resources_for_formats()
        except Exception:
            raise MalformedPolicyDocumentException("The policy failed legacy parsing")
        try:
            self._validate_sid_uniqueness()
        except Exception:
            raise MalformedPolicyDocumentException(
                "Statement IDs (SID) in a single policy must be unique."
            )
        try:
            self._validate_action_like_exist()
        except Exception:
            raise MalformedPolicyDocumentException("Policy statement must contain actions.")

        if self._resource_error != "":
            raise MalformedPolicyDocumentException(self._resource_error)

        self._validate_actions_for_prefixes()
        self._validate_not_actions_for_prefixes()

    def _validate_syntax(self) -> None:
        self._policy_json = json.loads(self._policy_document)
        assert isinstance(self._policy_json, dict)
        self._validate_top_elements()
        self._validate_version_syntax()
        self._validate_id_syntax()
        self._validate_statements_syntax()

    def _validate_top_elements(self) -> None:
        top_elements = self._policy_json.keys()
        for element in top_elements:
            assert element in VALID_TOP_ELEMENTS

    def _validate_version_syntax(self) -> None:
        if "Version" in self._policy_json:
            assert self._policy_json["Version"] in VALID_VERSIONS

    def _validate_version(self) -> None:
        assert self._policy_json["Version"] == "2012-10-17"

    def _validate_sid_uniqueness(self) -> None:
        sids = []
        for statement in self._statements:
            if "Sid" in statement:
                statementId = statement["Sid"]
                if statementId:
                    assert statementId not in sids
                    sids.append(statementId)

    def _validate_statements_syntax(self) -> None:
        assert "Statement" in self._policy_json
        assert isinstance(self._policy_json["Statement"], (dict, list))

        if isinstance(self._policy_json["Statement"], dict):
            self._statements.append(self._policy_json["Statement"])
        else:
            self._statements += self._policy_json["Statement"]

        assert self._statements
        for statement in self._statements:
            self._validate_statement_syntax(statement)

    @staticmethod
    def _validate_statement_syntax(statement: dict[str, Any]) -> None:
        assert isinstance(statement, dict)
        for statement_element in statement.keys():
            assert statement_element in VALID_STATEMENT_ELEMENTS

        assert "Resource" not in statement or "NotResource" not in statement
        assert "Action" not in statement or "NotAction" not in statement

        IAMPolicyDocumentValidator._validate_effect_syntax(statement)
        IAMPolicyDocumentValidator._validate_action_syntax(statement)
        IAMPolicyDocumentValidator._validate_not_action_syntax(statement)
        IAMPolicyDocumentValidator._validate_resource_syntax(statement)
        IAMPolicyDocumentValidator._validate_not_resource_syntax(statement)
        IAMPolicyDocumentValidator._validate_condition_syntax(statement)
        IAMPolicyDocumentValidator._validate_sid_syntax(statement)

    @staticmethod
    def _validate_effect_syntax(statement: dict[str, Any]) -> None:
        assert "Effect" in statement
        assert isinstance(statement["Effect"], str)
        assert statement["Effect"].lower() in [
            allowed_effect.lower() for allowed_effect in VALID_EFFECTS
        ]

    @staticmethod
    def _validate_action_syntax(statement: dict[str, Any]) -> None:
        IAMPolicyDocumentValidator._validate_string_or_list_of_strings_syntax(statement, "Action")

    @staticmethod
    def _validate_not_action_syntax(statement: dict[str, Any]) -> None:
        IAMPolicyDocumentValidator._validate_string_or_list_of_strings_syntax(
            statement, "NotAction"
        )

    @staticmethod
    def _validate_resource_syntax(statement: dict[str, Any]) -> None:
        IAMPolicyDocumentValidator._validate_string_or_list_of_strings_syntax(statement, "Resource")

    @staticmethod
    def _validate_not_resource_syntax(statement: dict[str, Any]) -> None:
        IAMPolicyDocumentValidator._validate_string_or_list_of_strings_syntax(
            statement, "NotResource"
        )

    @staticmethod
    def _validate_string_or_list_of_strings_syntax(
        statement: dict[str, Any],
        key: str,
    ) -> None:
        if key in statement:
            assert isinstance(statement[key], (str, list))
            if isinstance(statement[key], list):
                for resource in statement[key]:
                    assert isinstance(resource, str)

    @staticmethod
    def _validate_condition_syntax(statement: dict[str, Any]) -> None:
        if "Condition" in statement:
            assert isinstance(statement["Condition"], dict)
            for condition_key, condition_value in statement["Condition"].items():
                assert isinstance(condition_value, dict)
                for condition_element_value in condition_value.values():
                    assert isinstance(condition_element_value, (list, str))

                if (
                    IAMPolicyDocumentValidator._strip_condition_key(condition_key)
                    not in VALID_CONDITIONS
                ):
                    assert not condition_value  # empty dict

    @staticmethod
    def _strip_condition_key(condition_key: str) -> str:
        for valid_prefix in VALID_CONDITION_PREFIXES:
            if condition_key.startswith(valid_prefix):
                condition_key = condition_key[len(valid_prefix) :]
                break  # strip only the first match

        for valid_postfix in VALID_CONDITION_POSTFIXES:
            if condition_key.endswith(valid_postfix):
                condition_key = condition_key[: -len(valid_postfix)]
                break  # strip only the first match

        return condition_key

    @staticmethod
    def _validate_sid_syntax(statement: dict[str, Any]) -> None:
        if "Sid" in statement:
            assert isinstance(statement["Sid"], str)

    def _validate_id_syntax(self) -> None:
        if "Id" in self._policy_json:
            assert isinstance(self._policy_json["Id"], str)

    def _validate_resource_exist(self) -> None:
        for statement in self._statements:
            assert "Resource" in statement or "NotResource" in statement
            if "Resource" in statement and isinstance(statement["Resource"], list):
                assert statement["Resource"]
            elif "NotResource" in statement and isinstance(statement["NotResource"], list):
                assert statement["NotResource"]

    def _validate_action_like_exist(self) -> None:
        for statement in self._statements:
            assert "Action" in statement or "NotAction" in statement
            if "Action" in statement and isinstance(statement["Action"], list):
                assert statement["Action"]
            elif "NotAction" in statement and isinstance(statement["NotAction"], list):
                assert statement["NotAction"]

    def _validate_actions_for_prefixes(self) -> None:
        self._validate_action_like_for_prefixes("Action")

    def _validate_not_actions_for_prefixes(self) -> None:
        self._validate_action_like_for_prefixes("NotAction")

    def _validate_action_like_for_prefixes(self, key: str) -> None:
        for statement in self._statements:
            if key in statement:
                if isinstance(statement[key], str):
                    self._validate_action_prefix(statement[key])
                else:
                    for action in statement[key]:
                        self._validate_action_prefix(action)

    @staticmethod
    def _validate_action_prefix(action: str) -> None:
        action_parts = action.split(":")
        if len(action_parts) == 1 and action_parts[0] != "*":
            raise MalformedPolicyDocumentException(
                "Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc."
            )
        elif len(action_parts) > 2:
            raise MalformedPolicyDocumentException("Actions/Condition can contain only one colon.")

        vendor_pattern = re.compile(r"[^a-zA-Z0-9\-.]")
        if action_parts[0] != "*" and vendor_pattern.search(action_parts[0]):
            raise MalformedPolicyDocumentException(f"Vendor {action_parts[0]} is not valid")

    def _validate_resources_for_formats(self) -> None:
        self._validate_resource_like_for_formats("Resource")

    def _validate_not_resources_for_formats(self) -> None:
        self._validate_resource_like_for_formats("NotResource")

    def _validate_resource_like_for_formats(self, key: str) -> None:
        for statement in self._statements:
            if key in statement:
                if isinstance(statement[key], str):
                    self._validate_resource_format(statement[key])
                else:
                    for resource in sorted(statement[key], reverse=True):
                        self._validate_resource_format(resource)
                if self._resource_error == "":
                    IAMPolicyDocumentValidator._legacy_parse_resource_like(statement, key)

    def _validate_resource_format(self, resource: str) -> None:
        if resource != "*":
            resource_partitions = resource.partition(":")

            if resource_partitions[1] == "":
                self._resource_error = f'Resource {resource} must be in ARN format or "*".'
                return

            resource_partitions = resource_partitions[2].partition(":")
            if resource_partitions[0] != "*" and resource_partitions[0] not in PARTITION_NAMES:
                remaining_resource_parts = resource_partitions[2].split(":")

                arn1 = (
                    remaining_resource_parts[0]
                    if remaining_resource_parts[0] != "" or len(remaining_resource_parts) > 1
                    else "*"
                )
                arn2 = remaining_resource_parts[1] if len(remaining_resource_parts) > 1 else "*"
                arn3 = remaining_resource_parts[2] if len(remaining_resource_parts) > 2 else "*"
                arn4 = (
                    ":".join(remaining_resource_parts[3:])
                    if len(remaining_resource_parts) > 3
                    else "*"
                )
                pt = resource_partitions[0]
                self._resource_error = f'Partition "{pt}" is not valid for resource "arn:{pt}:{arn1}:{arn2}:{arn3}:{arn4}".'
                return

            if resource_partitions[1] != ":":
                self._resource_error = (
                    "Resource vendor must be fully qualified and cannot contain regexes."
                )
                return

            resource_partitions = resource_partitions[2].partition(":")

            service = resource_partitions[0]
            region = resource_partitions[2]
            resource_partitions = resource_partitions[2].partition(":")

            resource_partitions = resource_partitions[2].partition(":")
            resource_id = resource_partitions[2]

            if (
                service in SERVICE_TYPE_REGION_INFORMATION_ERROR_ASSOCIATIONS.keys()
                and not region.startswith(":")
            ):
                valid_start = False

                for valid_starting_value in SERVICE_TYPE_REGION_INFORMATION_ERROR_ASSOCIATIONS[
                    service
                ].get("valid_starting_values", []):
                    if resource_id.startswith(valid_starting_value):
                        valid_start = True
                        break

                if not valid_start:
                    self._resource_error = SERVICE_TYPE_REGION_INFORMATION_ERROR_ASSOCIATIONS[
                        service
                    ]["error_message"].format(resource=resource)
                    return

            if service in VALID_RESOURCE_PATH_STARTING_VALUES.keys():
                valid_start = False
                for valid_starting_value in VALID_RESOURCE_PATH_STARTING_VALUES[service]["values"]:
                    if resource_partitions[2].startswith(valid_starting_value):
                        valid_start = True
                        break
                if not valid_start:
                    self._resource_error = VALID_RESOURCE_PATH_STARTING_VALUES[service][
                        "error_message"
                    ].format(
                        values=", ".join(VALID_RESOURCE_PATH_STARTING_VALUES[service]["values"])
                    )

    def _perform_first_legacy_parsing(self) -> None:
        """This method excludes legacy parsing resources, since that have to be done later."""
        for statement in self._statements:
            self._legacy_parse_statement(statement)

    @staticmethod
    def _legacy_parse_statement(statement: dict[str, Any]) -> None:
        assert statement["Effect"] in VALID_EFFECTS  # case-sensitive matching
        if "Condition" in statement:
            for condition_key, condition_value in statement["Condition"].items():
                IAMPolicyDocumentValidator._legacy_parse_condition(condition_key, condition_value)

    @staticmethod
    def _legacy_parse_resource_like(statement: dict[str, Any], key: str) -> None:
        if isinstance(statement[key], str):
            if statement[key] != "*":
                assert statement[key].count(":") >= 5 or "::" not in statement[key]
                assert statement[key].split(":")[2] != ""
        else:  # list
            for resource in statement[key]:
                if resource != "*":
                    assert resource.count(":") >= 5 or "::" not in resource
                    assert resource[2] != ""

    @staticmethod
    def _legacy_parse_condition(
        condition_key: str,
        condition_value: dict[str, Any],
    ) -> None:
        stripped_condition_key = IAMPolicyDocumentValidator._strip_condition_key(condition_key)

        if stripped_condition_key.startswith("Date"):
            for condition_element_value in condition_value.values():
                if isinstance(condition_element_value, str):
                    IAMPolicyDocumentValidator._legacy_parse_date_condition_value(
                        condition_element_value
                    )
                else:  # it has to be a list
                    for date_condition_value in condition_element_value:
                        IAMPolicyDocumentValidator._legacy_parse_date_condition_value(
                            date_condition_value
                        )

    @staticmethod
    def _legacy_parse_date_condition_value(date_condition_value: str) -> None:
        if "t" in date_condition_value.lower() or "-" in date_condition_value:
            IAMPolicyDocumentValidator._validate_iso_8601_datetime(date_condition_value.lower())
        else:  # timestamp
            assert 0 <= int(date_condition_value) <= 9223372036854775807

    @staticmethod
    def _validate_iso_8601_datetime(datetime: str) -> None:
        datetime_parts = datetime.partition("t")
        negative_year = datetime_parts[0].startswith("-")
        date_parts = (
            datetime_parts[0][1:].split("-") if negative_year else datetime_parts[0].split("-")
        )
        year = "-" + date_parts[0] if negative_year else date_parts[0]
        assert -292275054 <= int(year) <= 292278993
        if len(date_parts) > 1:
            month = date_parts[1]
            assert 1 <= int(month) <= 12
        if len(date_parts) > 2:
            day = date_parts[2]
            assert 1 <= int(day) <= 31
        assert len(date_parts) < 4

        time_parts = datetime_parts[2].split(":")
        if time_parts[0] != "":
            hours = time_parts[0]
            assert 0 <= int(hours) <= 23
        if len(time_parts) > 1:
            minutes = time_parts[1]
            assert 0 <= int(minutes) <= 59
        if len(time_parts) > 2:
            if "z" in time_parts[2]:
                seconds_with_decimal_fraction = time_parts[2].partition("z")[0]
                assert time_parts[2].partition("z")[2] == ""
            elif "+" in time_parts[2]:
                seconds_with_decimal_fraction = time_parts[2].partition("+")[0]
                time_zone_data = time_parts[2].partition("+")[2].partition(":")
                time_zone_hours = time_zone_data[0]
                assert len(time_zone_hours) == 2
                assert 0 <= int(time_zone_hours) <= 23
                if time_zone_data[1] == ":":
                    time_zone_minutes = time_zone_data[2]
                    assert len(time_zone_minutes) == 2
                    assert 0 <= int(time_zone_minutes) <= 59
            else:
                seconds_with_decimal_fraction = time_parts[2]
            seconds_with_decimal_fraction_partition = seconds_with_decimal_fraction.partition(".")
            seconds = seconds_with_decimal_fraction_partition[0]
            assert 0 <= int(seconds) <= 59
            if seconds_with_decimal_fraction_partition[1] == ".":
                decimal_seconds = seconds_with_decimal_fraction_partition[2]
                assert 0 <= int(decimal_seconds) <= 999999999


class IAMPolicyDocumentValidator(BaseIAMPolicyValidator):
    def __init__(self, policy_document: str):
        super().__init__(policy_document)

    def validate(self) -> None:
        super().validate()
        try:
            self._validate_resource_exist()
        except Exception:
            raise MalformedPolicyDocumentException("Policy statement must contain resources.")


class IAMTrustPolicyDocumentValidator(BaseIAMPolicyValidator):
    def __init__(self, policy_document: str):
        super().__init__(policy_document)

    def validate(self) -> None:
        super().validate()
        try:
            for statement in self._statements:
                if isinstance(statement["Action"], str):
                    IAMTrustPolicyDocumentValidator._validate_trust_policy_action(
                        statement["Action"]
                    )
                else:
                    for action in statement["Action"]:
                        IAMTrustPolicyDocumentValidator._validate_trust_policy_action(action)
        except Exception:
            raise MalformedPolicyDocumentException(
                "Trust Policy statement actions can only be sts:AssumeRole, "
                "sts:AssumeRoleWithSAML,  and sts:AssumeRoleWithWebIdentity"
            )
        try:
            self._validate_resource_not_exist()
        except Exception:
            raise MalformedPolicyDocumentException("Has prohibited field Resource.")

    def _validate_resource_not_exist(self) -> None:
        for statement in self._statements:
            assert "Resource" not in statement and "NotResource" not in statement

    @staticmethod
    def _validate_trust_policy_action(action: str) -> None:
        # https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecuritytokenservice.html
        assert action in (
            "sts:AssumeRole",
            "sts:AssumeRoleWithSAML",
            "sts:AssumeRoleWithWebIdentity",
            "sts:DecodeAuthorizationMessage",
            "sts:GetAccessKeyInfo",
            "sts:GetCallerIdentity",
            "sts:GetFederationToken",
            "sts:GetServiceBearerToken",
            "sts:GetSessionToken",
            "sts:SetSourceIdentity",
            "sts:TagSession",
        )
