import json
import typing as t

from localstack.aws.api.sns import InvalidParameterException


class SubscriptionFilter:
    def check_filter_policy_on_message_attributes(
        self, filter_policy: dict, message_attributes: dict
    ):
        for criteria, conditions in filter_policy.items():
            if not self._evaluate_filter_policy_conditions_on_attribute(
                conditions,
                message_attributes.get(criteria),
                field_exists=criteria in message_attributes,
            ):
                return False

        return True

    def check_filter_policy_on_message_body(self, filter_policy: dict, message_body: str):
        try:
            body = json.loads(message_body)
            if not isinstance(body, dict):
                return False
        except json.JSONDecodeError:
            # Filter policies for the message body assume that the message payload is a well-formed JSON object.
            # See https://docs.aws.amazon.com/sns/latest/dg/sns-message-filtering.html
            return False

        return self._evaluate_nested_filter_policy_on_dict(filter_policy, payload=body)

    def _evaluate_nested_filter_policy_on_dict(self, filter_policy, payload: dict) -> bool:
        """
        This method evaluates the filter policy against the JSON decoded payload.
        Although it's not documented anywhere, AWS allows `.` in the fields name in the filter policy and the payload,
        and will evaluate them. However, it's not JSONPath compatible:
        Example:
        Policy: `{"field1.field2": "value1"}`
        This policy will match both `{"field1.field2": "value1"}` and  {"field1: {"field2": "value1"}}`, unlike JSONPath
        for which `.` points to a child node.
        This might show they are flattening the both dictionaries to a single level for an easier matching without
        recursion.
        :param filter_policy: a dict, starting at the FilterPolicy
        :param payload: a dict, starting at the MessageBody
        :return: True if the payload respect the filter policy, otherwise False
        """
        flat_policy = self._flatten_dict(filter_policy)
        flat_payloads = self._flatten_dict_with_list(payload)
        for key, values in flat_policy.items():
            if not any(
                self._evaluate_condition(
                    flat_payload.get(key), condition, field_exists=key in flat_payload
                )
                for condition in values
                for flat_payload in flat_payloads
            ):
                return False
        return True

    def _evaluate_filter_policy_conditions_on_attribute(
        self, conditions, attribute, field_exists: bool
    ):
        if not isinstance(conditions, list):
            conditions = [conditions]

        tpe = attribute.get("DataType") or attribute.get("Type") if attribute else None
        val = attribute.get("StringValue") or attribute.get("Value") if attribute else None
        if attribute is not None and tpe == "String.Array":
            try:
                values = json.loads(val)
            except ValueError:
                return False
            for value in values:
                for condition in conditions:
                    if self._evaluate_condition(value, condition, field_exists):
                        return True
        else:
            for condition in conditions:
                value = val or None
                if self._evaluate_condition(value, condition, field_exists):
                    return True

        return False

    def _evaluate_condition(self, value, condition, field_exists: bool):
        if not isinstance(condition, dict):
            return field_exists and value == condition
        elif (must_exist := condition.get("exists")) is not None:
            # if must_exists is True then field_exists must be True
            # if must_exists is False then fields_exists must be False
            return must_exist == field_exists
        elif value is None:
            # the remaining conditions require the value to not be None
            return False
        elif anything_but := condition.get("anything-but"):
            # TODO: support with `prefix`
            # https://docs.aws.amazon.com/sns/latest/dg/string-value-matching.html#string-anything-but-matching-prefix
            return value not in anything_but
        elif prefix := (condition.get("prefix")):
            return value.startswith(prefix)
        elif numeric_condition := condition.get("numeric"):
            return self._evaluate_numeric_condition(numeric_condition, value)
        return False

    @staticmethod
    def _evaluate_numeric_condition(conditions, value):
        try:
            # try if the value is numeric
            value = float(value)
        except ValueError:
            # the value is not numeric, the condition is False
            return False

        for i in range(0, len(conditions), 2):
            operator = conditions[i]
            operand = float(conditions[i + 1])

            if operator == "=":
                if value != operand:
                    return False
            elif operator == ">":
                if value <= operand:
                    return False
            elif operator == "<":
                if value >= operand:
                    return False
            elif operator == ">=":
                if value < operand:
                    return False
            elif operator == "<=":
                if value > operand:
                    return False

        return True

    @staticmethod
    def _flatten_dict(nested_dict: dict):
        """
        Takes a dictionary as input and will output the dictionary on a single level.
        Input:
        `{"field1": {"field2: {"field3: "val1", "field4": "val2"}}}`
        Output:
        `{
            "field1.field2.field3": "val1",
            "field1.field2.field4": "val1"
        }`
        :param nested_dict: a (nested) dictionary
        :return: a list of flattened dictionaries with no nested dict or list inside, flattened to a
        single level, one list item for every list item encountered
        """
        flatten = {}

        def _traverse(_policy: dict, parent_key=None):
            for key, values in _policy.items():
                flattened_parent_key = key if not parent_key else f"{parent_key}.{key}"
                if not isinstance(values, dict):
                    flatten[flattened_parent_key] = values
                else:
                    _traverse(values, parent_key=flattened_parent_key)

        _traverse(nested_dict)
        return flatten

    @staticmethod
    def _flatten_dict_with_list(nested_dict: dict) -> list[dict]:
        """
        Takes a dictionary as input and will output the dictionary on a single level.
        The dictionary can have lists containing other dictionaries, and one root level entry will be created for every
        item in a list.
        Input:
        `{"field1": {
            "field2: [
                {"field3: "val1", "field4": "val2"},
                {"field3: "val3", "field4": "val4"},
            }
        ]}`
        Output:
        `[
            {
                "field1.field2.field3": "val1",
                "field1.field2.field4": "val2"
            },
            {
                "field1.field2.field3": "val3",
                "field1.field2.field4": "val4"
            },
        ]`
        :param nested_dict: a (nested) dictionary
        :return: flatten_dict: a dictionary with no nested dict inside, flattened to a single level
        """
        flattened = []
        current_object = {}

        def _traverse(_object, parent_key=None):
            if isinstance(_object, dict):
                for key, values in _object.items():
                    flattened_parent_key = key if not parent_key else f"{parent_key}.{key}"
                    _traverse(values, flattened_parent_key)

            # we don't have to worry about `parent_key` being None for list or any other type, because we have a check
            # that the first object is always a dict, thus setting a parent key on first iteration
            elif isinstance(_object, list):
                for value in _object:
                    if isinstance(value, (dict, list)):
                        _traverse(value, parent_key=parent_key)
                    else:
                        current_object[parent_key] = value

                    if current_object:
                        flattened.append({**current_object})
                        current_object.clear()
            else:
                current_object[parent_key] = _object

        _traverse(nested_dict)

        # if the payload did not have any list, we manually append the current object
        if not flattened:
            flattened.append(current_object)

        return flattened


class FilterPolicyValidator:
    def __init__(self, scope: str, is_subscribe_call: bool):
        self.scope = scope
        self.error_prefix = (
            "Invalid parameter: Attributes Reason: " if is_subscribe_call else "Invalid parameter: "
        )

    def validate_filter_policy(self, filter_policy: dict[str, t.Any]):
        # # A filter policy can have a maximum of five attribute names. For a nested policy, only parent keys are counted.
        if len(filter_policy.values()) > 5:
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Filter policy can not have more than 5 keys"
            )

        aggregated_rules, combinations = self.aggregate_rules(filter_policy)
        # For the complexity of the filter policy, the total combination of values must not exceed 150.
        # https://docs.aws.amazon.com/sns/latest/dg/subscription-filter-policy-constraints.html
        if combinations > 150:
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Filter policy is too complex"
            )

        for rules in aggregated_rules:
            for rule in rules:
                self._validate_rule(rule)

    def aggregate_rules(self, filter_policy: dict[str, t.Any]) -> tuple[list[list[t.Any]], int]:
        """
        This method evaluate the filter policy recursively, and returns only a list of lists of rules.
        It also calculates the combinations of rules, calculated depending on the nesting of the rules.
        Example:
        nested_filter_policy = {
            "key_a": {
                "key_b": {
                    "key_c": ["value_one", "value_two", "value_three", "value_four"]
                }
            },
            "key_d": {
                "key_e": ["value_one", "value_two", "value_three"]
            }
        }
        This function then iterates on the values of the top level keys of the filter policy: ("key_a", "key_d")
        If the iterated value is not a list, it means it is a nested property. If the scope is `MessageBody`, it is
        allowed, we call this method on the value, adding a level to the depth to keep track on how deep the key is.
        If the value is a list, it means it contains rules: we will append this list of rules in _rules, and
        calculate the combinations it adds.
        For the example filter policy containing nested properties, we calculate it this way
        The first array has four values in a three-level nested key, and the second has three values in a two-level
        nested key. 3 x 4 x 2 x 3 = 72
        The return value would be:
        [["value_one", "value_two", "value_three", "value_four"], ["value_one", "value_two", "value_three"]]
        It allows us to later iterate of the list of rules in an easy way, to verify its conditions only.

        :param filter_policy: a dict, starting at the FilterPolicy
        :return: a tuple with a list of lists of rules and the calculated number of combinations
        """

        def _inner(
            policy_elements: dict[str, t.Any], depth: int = 1, combinations: int = 1
        ) -> tuple[list[list[t.Any]], int]:
            _rules = []
            for key, _value in policy_elements.items():
                if isinstance(_value, dict):
                    # From AWS docs: "unlike attribute-based policies, payload-based policies support property nesting."
                    sub_rules, combinations = _inner(
                        _value, depth=depth + 1, combinations=combinations
                    )
                    _rules.extend(sub_rules)
                elif isinstance(_value, list):
                    current_combination = 0
                    if key == "$or":
                        for val in _value:
                            sub_rules, or_combinations = _inner(
                                val, depth=depth, combinations=combinations
                            )
                            _rules.extend(sub_rules)
                            current_combination += or_combinations

                        combinations = current_combination
                    else:
                        _rules.append(_value)
                        combinations = combinations * len(_value) * depth
                else:
                    raise InvalidParameterException(
                        f'{self.error_prefix}FilterPolicy: "{key}" must be an object or an array'
                    )

            if self.scope == "MessageAttributes" and depth > 1:
                raise InvalidParameterException(
                    f"{self.error_prefix}Filter policy scope MessageAttributes does not support nested filter policy"
                )

            return _rules, combinations

        return _inner(filter_policy)

    def _validate_rule(self, rule: t.Any) -> None:
        match rule:
            case None | str() | bool():
                return

            case int() | float():
                # TODO: AWS says they support only from -10^9 to 10^9 but seems to accept it, so we just return
                # if rule <= -1000000000 or rule >= 1000000000:
                #     raise ""
                return

            case {**kwargs}:
                if len(kwargs) != 1:
                    raise InvalidParameterException(
                        f"{self.error_prefix}FilterPolicy: Only one key allowed in match expression"
                    )

                operator, value = None, None
                for k, v in kwargs.items():
                    operator, value = k, v

                if operator in (
                    "anything-but",
                    "equals-ignore-case",
                    "prefix",
                    "suffix",
                ):
                    if not isinstance(value, str):
                        raise InvalidParameterException(
                            f"{self.error_prefix}FilterPolicy: {operator} match pattern must be a string"
                        )
                    return

                elif operator == "exists":
                    if not isinstance(value, bool):
                        raise InvalidParameterException(
                            f"{self.error_prefix}FilterPolicy: exists match pattern must be either true or false."
                        )
                    return

                elif operator == "numeric":
                    self._validate_numeric_condition(value)

                else:
                    raise InvalidParameterException(
                        f"{self.error_prefix}FilterPolicy: Unrecognized match type {operator}"
                    )

            case _:
                raise InvalidParameterException(
                    f"{self.error_prefix}FilterPolicy: Match value must be String, number, true, false, or null"
                )

    def _validate_numeric_condition(self, value):
        if not value:
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Invalid member in numeric match: ]"
            )
        num_values = value[::-1]

        operator = num_values.pop()
        if not isinstance(operator, str):
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Invalid member in numeric match: {operator}"
            )
        elif operator not in ("<", "<=", "=", ">", ">="):
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Unrecognized numeric range operator: {operator}"
            )

        value = num_values.pop() if num_values else None
        if not isinstance(value, (int, float)):
            exc_operator = "equals" if operator == "=" else operator
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Value of {exc_operator} must be numeric"
            )

        if not num_values:
            return

        if operator not in (">", ">="):
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Too many elements in numeric expression"
            )

        second_operator = num_values.pop()
        if not isinstance(second_operator, str):
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Bad value in numeric range: {second_operator}"
            )
        elif second_operator not in ("<", "<="):
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Bad numeric range operator: {second_operator}"
            )

        second_value = num_values.pop() if num_values else None
        if not isinstance(second_value, (int, float)):
            exc_operator = "equals" if second_operator == "=" else second_operator
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Value of {exc_operator} must be numeric"
            )

        elif second_value <= value:
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Bottom must be less than top"
            )

        elif num_values:
            raise InvalidParameterException(
                f"{self.error_prefix}FilterPolicy: Too many terms in numeric range expression"
            )
