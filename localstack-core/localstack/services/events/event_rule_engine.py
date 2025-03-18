import ipaddress
import json
import re
import typing as t

from localstack.aws.api.events import InvalidEventPatternException


class EventRuleEngine:
    def evaluate_pattern_on_event(self, compiled_event_pattern: dict, event: str | dict):
        if isinstance(event, str):
            try:
                body = json.loads(event)
                if not isinstance(body, dict):
                    return False
            except json.JSONDecodeError:
                # Event pattern for the message body assume that the message payload is a well-formed JSON object.
                return False
        else:
            body = event

        return self._evaluate_nested_event_pattern_on_dict(compiled_event_pattern, payload=body)

    def _evaluate_nested_event_pattern_on_dict(self, event_pattern, payload: dict) -> bool:
        """
        This method evaluates the event pattern against the JSON decoded payload.
        Although it's not documented anywhere, AWS allows `.` in the fields name in the event pattern and the payload,
        and will evaluate them. However, it's not JSONPath compatible.
        See:
        https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern.html#eb-create-pattern-considerations
        Example:
        Pattern: `{"field1.field2": "value1"}`
        This pattern will match both `{"field1.field2": "value1"}` and  {"field1: {"field2": "value1"}}`, unlike JSONPath
        for which `.` points to a child node.
        This might show they are flattening the both dictionaries to a single level for an easier matching without
        recursion.
        :param event_pattern: a dict, starting at the Event Pattern
        :param payload: a dict, starting at the MessageBody
        :return: True if the payload respect the event pattern, otherwise False
        """
        if not event_pattern:
            return True

        # TODO: maybe save/cache the flattened/expanded pattern?
        flat_pattern_conditions = self.flatten_pattern(event_pattern)
        flat_payloads = self.flatten_payload(payload, flat_pattern_conditions)

        return any(
            all(
                any(
                    self._evaluate_condition(
                        flat_payload.get(key), condition, field_exists=key in flat_payload
                    )
                    for condition in conditions
                    for flat_payload in flat_payloads
                )
                for key, conditions in flat_pattern.items()
            )
            for flat_pattern in flat_pattern_conditions
        )

    def _evaluate_condition(self, value, condition, field_exists: bool):
        if not isinstance(condition, dict):
            return field_exists and value == condition
        elif (must_exist := condition.get("exists")) is not None:
            # if must_exists is True then field_exists must be True
            # if must_exists is False then fields_exists must be False
            return must_exist == field_exists
        elif (anything_but := condition.get("anything-but")) is not None:
            if isinstance(anything_but, dict):
                if (not_condition := anything_but.get("prefix")) is not None:
                    predicate = self._evaluate_prefix
                elif (not_condition := anything_but.get("suffix")) is not None:
                    predicate = self._evaluate_suffix
                elif (not_condition := anything_but.get("equals-ignore-case")) is not None:
                    predicate = self._evaluate_equal_ignore_case
                elif (not_condition := anything_but.get("wildcard")) is not None:
                    predicate = self._evaluate_wildcard
                else:
                    # this should not happen as we validate the EventPattern before
                    return False

                if isinstance(not_condition, str):
                    return not predicate(not_condition, value)
                elif isinstance(not_condition, list):
                    return all(
                        not predicate(sub_condition, value) for sub_condition in not_condition
                    )

            elif isinstance(anything_but, list):
                return value not in anything_but
            else:
                return value != anything_but

        elif value is None:
            # the remaining conditions require the value to not be None
            return False
        elif (prefix := condition.get("prefix")) is not None:
            if isinstance(prefix, dict):
                if (prefix_equal_ignore_case := prefix.get("equals-ignore-case")) is not None:
                    return self._evaluate_prefix(prefix_equal_ignore_case.lower(), value.lower())
            else:
                return self._evaluate_prefix(prefix, value)

        elif (suffix := condition.get("suffix")) is not None:
            if isinstance(suffix, dict):
                if suffix_equal_ignore_case := suffix.get("equals-ignore-case"):
                    return self._evaluate_suffix(suffix_equal_ignore_case.lower(), value.lower())
            else:
                return self._evaluate_suffix(suffix, value)

        elif (equal_ignore_case := condition.get("equals-ignore-case")) is not None:
            return self._evaluate_equal_ignore_case(equal_ignore_case, value)

        # we validated that `numeric`  should be a non-empty list when creating the rule, we don't need the None check
        elif numeric_condition := condition.get("numeric"):
            return self._evaluate_numeric_condition(numeric_condition, value)

        # we also validated the `cidr` that it cannot be empty
        elif cidr := condition.get("cidr"):
            return self._evaluate_cidr(cidr, value)

        elif (wildcard := condition.get("wildcard")) is not None:
            return self._evaluate_wildcard(wildcard, value)

        return False

    @staticmethod
    def _evaluate_prefix(condition: str | list, value: str) -> bool:
        return value.startswith(condition)

    @staticmethod
    def _evaluate_suffix(condition: str | list, value: str) -> bool:
        return value.endswith(condition)

    @staticmethod
    def _evaluate_equal_ignore_case(condition: str, value: str) -> bool:
        return condition.lower() == value.lower()

    @staticmethod
    def _evaluate_cidr(condition: str, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
            return ip in ipaddress.ip_network(condition)
        except ValueError:
            return False

    @staticmethod
    def _evaluate_wildcard(condition: str, value: str) -> bool:
        return bool(re.match(re.escape(condition).replace("\\*", ".+") + "$", value))

    @staticmethod
    def _evaluate_numeric_condition(conditions: list, value: t.Any) -> bool:
        if not isinstance(value, (int, float)):
            return False
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
    def flatten_pattern(nested_dict: dict) -> list[dict]:
        """
        Takes a dictionary as input and will output the dictionary on a single level.
        Input:
        `{"field1": {"field2": {"field3": "val1", "field4": "val2"}}}`
        Output:
        `[
            {
                "field1.field2.field3": "val1",
                "field1.field2.field4": "val2"
            }
        ]`
        Input with $or will create multiple outputs:
        `{"$or": [{"field1": "val1"}, {"field2": "val2"}], "field3": "val3"}`
        Output:
        `[
            {"field1": "val1", "field3": "val3"},
            {"field2": "val2", "field3": "val3"}
        ]`
        :param nested_dict: a (nested) dictionary
        :return: a list of flattened dictionaries with no nested dict or list inside, flattened to a
        single level, one list item for every list item encountered
        """

        def _traverse_event_pattern(obj, array=None, parent_key=None) -> list:
            if array is None:
                array = [{}]

            for key, values in obj.items():
                if key == "$or" and isinstance(values, list) and len(values) > 1:
                    # $or will create multiple new branches in the array.
                    # Each current branch will traverse with each choice in $or
                    array = [
                        i
                        for value in values
                        for i in _traverse_event_pattern(value, array, parent_key)
                    ]
                else:
                    # We update the parent key do that {"key1": {"key2": ""}} becomes "key1.key2"
                    _parent_key = f"{parent_key}.{key}" if parent_key else key
                    if isinstance(values, dict):
                        # If the current key has child dict -- key: "key1", child: {"key2": ["val1", val2"]}
                        # We only update the parent_key and traverse its children with the current branches
                        array = _traverse_event_pattern(values, array, _parent_key)
                    else:
                        # If the current key has no child, this means we found the values to match -- child: ["val1", val2"]
                        # we update the branches with the parent chain and the values -- {"key1.key2": ["val1, val2"]}
                        array = [{**item, _parent_key: values} for item in array]

            return array

        return _traverse_event_pattern(nested_dict)

    @staticmethod
    def flatten_payload(payload: dict, patterns: list[dict]) -> list[dict]:
        """
        Takes a dictionary as input and will output the dictionary on a single level.
        The dictionary can have lists containing other dictionaries, and one root level entry will be created for every
        item in a list if it corresponds to the entries of the patterns.
        Input:
        payload:
        `{"field1": {
            "field2: [
                {"field3: "val1", "field4": "val2"},
                {"field3: "val3", "field4": "val4"},
            }
        ]}`
        patterns:
        `[
            "field1.field2.field3": <condition>,
            "field1.field2.field4": <condition>,
        ]`
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
        :param payload: a (nested) dictionary, the event payload
        :param patterns: the flattened patterns from the EventPattern (see flatten_pattern)
        :return: flatten_dict: a dictionary with no nested dict inside, flattened to a single level
        """
        patterns_keys = {key for keys in patterns for key in keys}

        def _is_key_in_patterns(key: str) -> bool:
            return key is None or any(pattern_key.startswith(key) for pattern_key in patterns_keys)

        def _traverse(_object: dict, array=None, parent_key=None) -> list:
            if isinstance(_object, dict):
                for key, values in _object.items():
                    # We update the parent key so that {"key1": {"key2": ""}} becomes "key1.key2"
                    _parent_key = f"{parent_key}.{key}" if parent_key else key

                    # we make sure that we are building only the relevant parts of the payload related to the pattern
                    # the payload could be very complex, and the pattern only applies to part of it
                    if _is_key_in_patterns(_parent_key):
                        array = _traverse(values, array, _parent_key)

            elif isinstance(_object, list):
                if not _object:
                    return array
                array = [i for value in _object for i in _traverse(value, array, parent_key)]
            else:
                array = [{**item, parent_key: _object} for item in array]
            return array

        return _traverse(payload, array=[{}], parent_key=None)


class EventPatternCompiler:
    def __init__(self):
        self.error_prefix = "Event pattern is not valid. Reason: "

    def compile_event_pattern(self, event_pattern: str | dict) -> dict[str, t.Any]:
        if isinstance(event_pattern, str):
            try:
                event_pattern = json.loads(event_pattern)
                if not isinstance(event_pattern, dict):
                    raise InvalidEventPatternException(
                        f"{self.error_prefix}Filter is not an object"
                    )
            except json.JSONDecodeError:
                # this error message is not in parity, as it is tightly coupled to AWS parsing engine
                raise InvalidEventPatternException(f"{self.error_prefix}Filter is not valid JSON")

        aggregated_rules, combinations = self.aggregate_rules(event_pattern)

        for rules in aggregated_rules:
            for rule in rules:
                self._validate_rule(rule)

        return event_pattern

    def aggregate_rules(self, event_pattern: dict[str, t.Any]) -> tuple[list[list[t.Any]], int]:
        """
        This method evaluate the event pattern recursively, and returns only a list of lists of rules.
        It also calculates the combinations of rules, calculated depending on the nesting of the rules.
        Example:
        nested_event_pattern = {
            "key_a": {
                "key_b": {
                    "key_c": ["value_one", "value_two", "value_three", "value_four"]
                }
            },
            "key_d": {
                "key_e": ["value_one", "value_two", "value_three"]
            }
        }
        This function then iterates on the values of the top level keys of the event pattern: ("key_a", "key_d")
        If the iterated value is not a list, it means it is a nested property. If the scope is `MessageBody`, it is
        allowed, we call this method on the value, adding a level to the depth to keep track on how deep the key is.
        If the value is a list, it means it contains rules: we will append this list of rules in _rules, and
        calculate the combinations it adds.
        For the example event pattern containing nested properties, we calculate it this way
        The first array has four values in a three-level nested key, and the second has three values in a two-level
        nested key. 3 x 4 x 2 x 3 = 72
        The return value would be:
        [["value_one", "value_two", "value_three", "value_four"], ["value_one", "value_two", "value_three"]]
        It allows us to later iterate of the list of rules in an easy way, to verify its conditions only.

        :param event_pattern: a dict, starting at the Event Pattern
        :return: a tuple with a list of lists of rules and the calculated number of combinations
        """

        def _inner(
            pattern_elements: dict[str, t.Any], depth: int = 1, combinations: int = 1
        ) -> tuple[list[list[t.Any]], int]:
            _rules = []
            for key, _value in pattern_elements.items():
                if isinstance(_value, dict):
                    # From AWS docs: "unlike attribute-based policies, payload-based policies support property nesting."
                    sub_rules, combinations = _inner(
                        _value, depth=depth + 1, combinations=combinations
                    )
                    _rules.extend(sub_rules)
                elif isinstance(_value, list):
                    if not _value:
                        raise InvalidEventPatternException(
                            f"{self.error_prefix}Empty arrays are not allowed"
                        )

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
                    raise InvalidEventPatternException(
                        f'{self.error_prefix}"{key}" must be an object or an array'
                    )

            return _rules, combinations

        return _inner(event_pattern)

    def _validate_rule(self, rule: t.Any, from_: str | None = None) -> None:
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
                    raise InvalidEventPatternException(
                        f"{self.error_prefix}Only one key allowed in match expression"
                    )

                operator, value = None, None
                for k, v in kwargs.items():
                    operator, value = k, v

                if operator in (
                    "prefix",
                    "suffix",
                ):
                    if from_ == "anything-but":
                        if isinstance(value, dict):
                            raise InvalidEventPatternException(
                                f"{self.error_prefix}Value of {from_} must be an array or single string/number value."
                            )

                        if not self._is_str_or_list_of_str(value):
                            raise InvalidEventPatternException(
                                f"{self.error_prefix}prefix/suffix match pattern must be a string"
                            )
                        elif not value:
                            raise InvalidEventPatternException(
                                f"{self.error_prefix}Null prefix/suffix not allowed"
                            )

                    elif isinstance(value, dict):
                        for inner_operator in value.keys():
                            if inner_operator != "equals-ignore-case":
                                raise InvalidEventPatternException(
                                    f"{self.error_prefix}Unsupported anything-but pattern: {inner_operator}"
                                )

                    elif not isinstance(value, str):
                        raise InvalidEventPatternException(
                            f"{self.error_prefix}{operator} match pattern must be a string"
                        )
                    return

                elif operator == "equals-ignore-case":
                    if from_ == "anything-but":
                        if not self._is_str_or_list_of_str(value):
                            raise InvalidEventPatternException(
                                f"{self.error_prefix}Inside {from_}/{operator} list, number|start|null|boolean is not supported."
                            )
                    elif not isinstance(value, str):
                        raise InvalidEventPatternException(
                            f"{self.error_prefix}{operator} match pattern must be a string"
                        )
                    return

                elif operator == "anything-but":
                    # anything-but can actually contain any kind of simple rule (str, number, and list)
                    if isinstance(value, list):
                        for v in value:
                            self._validate_rule(v)

                        return

                    # or have a nested `prefix`, `suffix` or `equals-ignore-case` pattern
                    elif isinstance(value, dict):
                        for inner_operator in value.keys():
                            if inner_operator not in (
                                "prefix",
                                "equals-ignore-case",
                                "suffix",
                                "wildcard",
                            ):
                                raise InvalidEventPatternException(
                                    f"{self.error_prefix}Unsupported anything-but pattern: {inner_operator}"
                                )

                    self._validate_rule(value, from_="anything-but")
                    return

                elif operator == "exists":
                    if not isinstance(value, bool):
                        raise InvalidEventPatternException(
                            f"{self.error_prefix}exists match pattern must be either true or false."
                        )
                    return

                elif operator == "numeric":
                    self._validate_numeric_condition(value)

                elif operator == "cidr":
                    self._validate_cidr_condition(value)

                elif operator == "wildcard":
                    if from_ == "anything-but" and isinstance(value, list):
                        for v in value:
                            self._validate_wildcard(v)
                    else:
                        self._validate_wildcard(value)

                else:
                    raise InvalidEventPatternException(
                        f"{self.error_prefix}Unrecognized match type {operator}"
                    )

            case _:
                raise InvalidEventPatternException(
                    f"{self.error_prefix}Match value must be String, number, true, false, or null"
                )

    def _validate_numeric_condition(self, value):
        if not isinstance(value, list):
            raise InvalidEventPatternException(
                f"{self.error_prefix}Value of numeric must be an array."
            )
        if not value:
            raise InvalidEventPatternException(
                f"{self.error_prefix}Invalid member in numeric match: ]"
            )
        num_values = value[::-1]

        operator = num_values.pop()
        if not isinstance(operator, str):
            raise InvalidEventPatternException(
                f"{self.error_prefix}Invalid member in numeric match: {operator}"
            )
        elif operator not in ("<", "<=", "=", ">", ">="):
            raise InvalidEventPatternException(
                f"{self.error_prefix}Unrecognized numeric range operator: {operator}"
            )

        value = num_values.pop() if num_values else None
        if not isinstance(value, (int, float)):
            exc_operator = "equals" if operator == "=" else operator
            raise InvalidEventPatternException(
                f"{self.error_prefix}Value of {exc_operator} must be numeric"
            )

        if not num_values:
            return

        if operator not in (">", ">="):
            raise InvalidEventPatternException(
                f"{self.error_prefix}Too many elements in numeric expression"
            )

        second_operator = num_values.pop()
        if not isinstance(second_operator, str):
            raise InvalidEventPatternException(
                f"{self.error_prefix}Bad value in numeric range: {second_operator}"
            )
        elif second_operator not in ("<", "<="):
            raise InvalidEventPatternException(
                f"{self.error_prefix}Bad numeric range operator: {second_operator}"
            )

        second_value = num_values.pop() if num_values else None
        if not isinstance(second_value, (int, float)):
            exc_operator = "equals" if second_operator == "=" else second_operator
            raise InvalidEventPatternException(
                f"{self.error_prefix}Value of {exc_operator} must be numeric"
            )

        elif second_value <= value:
            raise InvalidEventPatternException(f"{self.error_prefix}Bottom must be less than top")

        elif num_values:
            raise InvalidEventPatternException(
                f"{self.error_prefix}Too many terms in numeric range expression"
            )

    def _validate_wildcard(self, value: t.Any):
        if not isinstance(value, str):
            raise InvalidEventPatternException(
                f"{self.error_prefix}wildcard match pattern must be a string"
            )
        # TODO: properly calculate complexity of wildcard
        # https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html#eb-filtering-wildcard-matching-complexity
        # > calculate complexity of repeating character sequences that occur after a wildcard character
        if "**" in value:
            raise InvalidEventPatternException(
                f"{self.error_prefix}Consecutive wildcard characters at pos {value.index('**') + 1}"
            )

        if value.count("*") > 5:
            raise InvalidEventPatternException(
                f"{self.error_prefix}Rule is too complex - try using fewer wildcard characters or fewer repeating character sequences after a wildcard character"
            )

    def _validate_cidr_condition(self, value):
        if not isinstance(value, str):
            # `cidr` returns the prefix error
            raise InvalidEventPatternException(
                f"{self.error_prefix}prefix match pattern must be a string"
            )
        ip_and_mask = value.split("/")
        if len(ip_and_mask) != 2:
            raise InvalidEventPatternException(
                f"{self.error_prefix}Malformed CIDR, one '/' required"
            )
        ip_addr, mask = value.split("/")
        try:
            int(mask)
        except ValueError:
            raise InvalidEventPatternException(
                f"{self.error_prefix}Malformed CIDR, mask bits must be an integer"
            )
        try:
            ipaddress.ip_network(value)
        except ValueError:
            raise InvalidEventPatternException(
                f"{self.error_prefix}Nonstandard IP address: {ip_addr}"
            )

    @staticmethod
    def _is_str_or_list_of_str(value: t.Any) -> bool:
        if not isinstance(value, (str, list)):
            return False
        if isinstance(value, list) and not all(isinstance(v, str) for v in value):
            return False

        return True
