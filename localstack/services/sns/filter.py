# import typing as t
# import json
#
#
# class SubscriptionFilter:
#     def check_filter_policy_on_message_attributes(
#         self, filter_policy: dict, message_attributes: dict
#     ):
#         if not filter_policy:
#             return True
#
#         flat_policy_conditions = self.flatten_policy(filter_policy)
#
#         return any(
#             all(
#                 self._evaluate_filter_policy_conditions_on_attribute(
#                     conditions,
#                     message_attributes.get(criteria),
#                     field_exists=criteria in message_attributes,
#                 )
#                 for criteria, conditions in flat_policy.items()
#             )
#             for flat_policy in flat_policy_conditions
#         )
#
#     def check_filter_policy_on_message_body(self, filter_policy: dict, message_body: str):
#         try:
#             body = json.loads(message_body)
#             if not isinstance(body, dict):
#                 return False
#         except json.JSONDecodeError:
#             # Filter policies for the message body assume that the message payload is a well-formed JSON object.
#             # See https://docs.aws.amazon.com/sns/latest/dg/sns-message-filtering.html
#             return False
#
#         return self._evaluate_nested_filter_policy_on_dict(filter_policy, payload=body)
#
#     def _evaluate_nested_filter_policy_on_dict(self, filter_policy, payload: dict) -> bool:
#         """
#         This method evaluates the filter policy against the JSON decoded payload.
#         Although it's not documented anywhere, AWS allows `.` in the fields name in the filter policy and the payload,
#         and will evaluate them. However, it's not JSONPath compatible:
#         Example:
#         Policy: `{"field1.field2": "value1"}`
#         This policy will match both `{"field1.field2": "value1"}` and  {"field1: {"field2": "value1"}}`, unlike JSONPath
#         for which `.` points to a child node.
#         This might show they are flattening the both dictionaries to a single level for an easier matching without
#         recursion.
#         :param filter_policy: a dict, starting at the FilterPolicy
#         :param payload: a dict, starting at the MessageBody
#         :return: True if the payload respect the filter policy, otherwise False
#         """
#         if not filter_policy:
#             return True
#
#         # TODO: maybe save/cache the flattened/expanded policy?
#         flat_policy_conditions = self.flatten_policy(filter_policy)
#         flat_payloads = self.flatten_payload(payload)
#
#         return any(
#             all(
#                 any(
#                     self._evaluate_condition(
#                         flat_payload.get(key), condition, field_exists=key in flat_payload
#                     )
#                     for condition in values
#                     for flat_payload in flat_payloads
#                 )
#                 for key, values in flat_policy.items()
#             )
#             for flat_policy in flat_policy_conditions
#         )
#
#     def _evaluate_filter_policy_conditions_on_attribute(
#         self, conditions, attribute, field_exists: bool
#     ):
#         if not isinstance(conditions, list):
#             conditions = [conditions]
#
#         tpe = attribute.get("DataType") or attribute.get("Type") if attribute else None
#         val = attribute.get("StringValue") or attribute.get("Value") if attribute else None
#         if attribute is not None and tpe == "String.Array":
#             try:
#                 values = json.loads(val)
#             except ValueError:
#                 return False
#             for value in values:
#                 for condition in conditions:
#                     if self._evaluate_condition(value, condition, field_exists):
#                         return True
#         else:
#             for condition in conditions:
#                 value = val or None
#                 if self._evaluate_condition(value, condition, field_exists):
#                     return True
#
#         return False
#
#     def _evaluate_condition(self, value, condition, field_exists: bool):
#         if not isinstance(condition, dict):
#             return field_exists and value == condition
#         elif (must_exist := condition.get("exists")) is not None:
#             # if must_exists is True then field_exists must be True
#             # if must_exists is False then fields_exists must be False
#             return must_exist == field_exists
#         elif value is None:
#             # the remaining conditions require the value to not be None
#             return False
#         elif anything_but := condition.get("anything-but"):
#             # TODO: anything-but can be combined with prefix (and maybe others) by putting another condition in
#             #  > "event":[{"anything-but": {"prefix": "order-"}}]
#             # > https://docs.aws.amazon.com/sns/latest/dg/string-value-matching.html#string-anything-but-matching-prefix
#             return value not in anything_but
#         elif prefix := condition.get("prefix"):
#             return value.startswith(prefix)
#         elif suffix := condition.get("suffix"):
#             return value.endswith(suffix)
#         elif equal_ignore_case := condition.get("equals-ignore-case"):
#             return equal_ignore_case.lower() == value.lower()
#         elif numeric_condition := condition.get("numeric"):
#             return self._evaluate_numeric_condition(numeric_condition, value)
#         return False
#
#     @staticmethod
#     def _evaluate_numeric_condition(conditions, value):
#         try:
#             # try if the value is numeric
#             value = float(value)
#         except ValueError:
#             # the value is not numeric, the condition is False
#             return False
#
#         for i in range(0, len(conditions), 2):
#             operator = conditions[i]
#             operand = float(conditions[i + 1])
#
#             if operator == "=":
#                 if value != operand:
#                     return False
#             elif operator == ">":
#                 if value <= operand:
#                     return False
#             elif operator == "<":
#                 if value >= operand:
#                     return False
#             elif operator == ">=":
#                 if value < operand:
#                     return False
#             elif operator == "<=":
#                 if value > operand:
#                     return False
#
#         return True
#
#     @staticmethod
#     def flatten_policy(nested_dict: dict) -> list[dict]:
#         """
#         Takes a dictionary as input and will output the dictionary on a single level.
#         Input:
#         `{"field1": {"field2": {"field3": "val1", "field4": "val2"}}}`
#         Output:
#         `[
#             {
#                 "field1.field2.field3": "val1",
#                 "field1.field2.field4": "val2"
#             }
#         ]`
#         Input with $or will create multiple outputs:
#         `{"$or": [{"field1": "val1"}, {"field2": "val2"}], "field3": "val3"}`
#         Output:
#         `[
#             {"field1": "val1", "field3": "val3"},
#             {"field2": "val2", "field3": "val3"}
#         ]`
#         :param nested_dict: a (nested) dictionary
#         :return: a list of flattened dictionaries with no nested dict or list inside, flattened to a
#         single level, one list item for every list item encountered
#         """
#
#         def _traverse_policy(obj, array=None, parent_key=None) -> list:
#             if array is None:
#                 array = [{}]
#
#             for key, values in obj.items():
#                 if key == "$or" and isinstance(values, list) and len(values) > 1:
#                     # $or will create multiple new branches in the array.
#                     # Each current branch will traverse with each choice in $or
#                     array = [
#                         i for value in values for i in _traverse_policy(value, array, parent_key)
#                     ]
#                 else:
#                     # We update the parent key do that {"key1": {"key2": ""}} becomes "key1.key2"
#                     _parent_key = f"{parent_key}.{key}" if parent_key else key
#                     if isinstance(values, dict):
#                         # If the current key has child dict -- key: "key1", child: {"key2": ["val1", val2"]}
#                         # We only update the parent_key and traverse its children with the current branches
#                         array = _traverse_policy(values, array, _parent_key)
#                     else:
#                         # If the current key has no child, this means we found the values to match -- child: ["val1", val2"]
#                         # we update the branches with the parent chain and the values -- {"key1.key2": ["val1, val2"]}
#                         array = [{**item, _parent_key: values} for item in array]
#
#             return array
#
#         return _traverse_policy(nested_dict)
#
#     @staticmethod
#     def flatten_payload(nested_dict: dict) -> list[dict]:
#         """
#         Takes a dictionary as input and will output the dictionary on a single level.
#         The dictionary can have lists containing other dictionaries, and one root level entry will be created for every
#         item in a list.
#         Input:
#         `{"field1": {
#             "field2: [
#                 {"field3: "val1", "field4": "val2"},
#                 {"field3: "val3", "field4": "val4"},
#             }
#         ]}`
#         Output:
#         `[
#             {
#                 "field1.field2.field3": "val1",
#                 "field1.field2.field4": "val2"
#             },
#             {
#                 "field1.field2.field3": "val3",
#                 "field1.field2.field4": "val4"
#             },
#         ]`
#         :param nested_dict: a (nested) dictionary
#         :return: flatten_dict: a dictionary with no nested dict inside, flattened to a single level
#         """
#         flattened = []
#         current_object = {}
#
#         def _traverse(_object, parent_key=None):
#             if isinstance(_object, dict):
#                 for key, values in _object.items():
#                     flattened_parent_key = key if not parent_key else f"{parent_key}.{key}"
#                     _traverse(values, flattened_parent_key)
#
#             # we don't have to worry about `parent_key` being None for list or any other type, because we have a check
#             # that the first object is always a dict, thus setting a parent key on first iteration
#             elif isinstance(_object, list):
#                 for value in _object:
#                     if isinstance(value, (dict, list)):
#                         _traverse(value, parent_key=parent_key)
#                     else:
#                         current_object[parent_key] = value
#
#                     if current_object:
#                         flattened.append({**current_object})
#                         current_object.clear()
#             else:
#                 current_object[parent_key] = _object
#
#         _traverse(nested_dict)
#
#         # if the payload did not have any list, we manually append the current object
#         if not flattened:
#             flattened.append(current_object)
#
#         return flattened
#
#
# def aggregate_rules(scope: str, filter_policy: dict[str, t.Any], depth: int = 1, combinations: int = 1) -> tuple[list[list[t.Any]], int]:
#     """
#     This method evaluate the filter policy recursively, and returns only a list of lists of rules.
#     It also calculates the combinations of rules, calculated depending on the nesting of the rules.
#     Example:
#     nested_filter_policy = {
#         "key_a": {
#             "key_b": {
#                 "key_c": ["value_one", "value_two", "value_three", "value_four"]
#             }
#         },
#         "key_d": {
#             "key_e": ["value_one", "value_two", "value_three"]
#         }
#     }
#     This function then iterates on the values of the top level keys of the filter policy: ("key_a", "key_d")
#     If the iterated value is not a list, it means it is a nested property. If the scope is `MessageBody`, it is
#     allowed, we call this method on the value, adding a level to the depth to keep track on how deep the key is.
#     If the value is a list, it means it contains rules: we will append this list of rules in _rules, and
#     calculate the combinations it adds.
#     For the example filter policy containing nested properties, we calculate it this way
#     The first array has four values in a three-level nested key, and the second has three values in a two-level
#     nested key. 3 x 4 x 2 x 3 = 72
#     The return value would be:
#     [["value_one", "value_two", "value_three", "value_four"], ["value_one", "value_two", "value_three"]]
#     It allows us to later iterate of the list of rules in an easy way, to verify its conditions.
#
#     :param filter_policy: a dict, starting at the FilterPolicy
#     :param depth: the depth/level of the rules we are evaluating
#     :param combinations: current numbers of combinations
#     :return: a list of lists of rules
#     """
#     # nonlocal combinations
#     _rules = []
#     for key, _value in filter_policy.items():
#         if isinstance(_value, dict):
#             if scope == "MessageBody":
#                 # From AWS docs: "unlike attribute-based policies, payload-based policies support property nesting."
#                 sub_rules, _ = aggregate_rules(scope, _value, depth=depth + 1)
#                 _rules.extend(sub_rules)
#             else:
#                 raise SNSInvalidParameter(
#                     "Invalid parameter: Filter policy scope MessageAttributes does not support nested filter policy"
#                 )
#         elif isinstance(_value, list):
#             if key == "$or":
#                 for val in _value:
#                     sub_rules, _ = aggregate_rules(scope, val, depth=depth + 1)
#                     _rules.extend(sub_rules)
#             else:
#                 _rules.append(_value)
#             combinations = combinations * len(_value) * depth
#         else:
#             raise SNSInvalidParameter(
#                 f'Invalid parameter: FilterPolicy: "{key}" must be an object or an array'
#             )
#     return _rules, combinations
#
#
#
# def _validate_rule(self, rule: t.Any) -> None:
#     match rule:
#         case None | str() | bool():
#             return
#
#         case int() | float():
#             if rule <= -1000000000 or rule >= 1000000000:
#                 raise ""
#             return
#
#         case {**kwargs}:
#             if len(kwargs) != 1:
#                 raise
#             operator, value = None, None
#             for k, v in kwargs.items():
#                 operator, value = k, v
#
#             if operator in (
#                 "anything-but",
#                 "equals-ignore-case",
#                 "prefix",
#                 "suffix",
#             ):
#                 # TODO: check if prefix/suffix/equals-ignore-case needs to be string
#                 return
#
#             elif operator == "exists":
#                 if not isinstance(value, bool):
#                     raise
#                 return
#
#             elif operator == "numeric":
#                 match kwargs:
#                     case ["" | "", val1,  "" | "", val2]:
#                         pass
#
#
#
#
#
#     if isinstance(rule, dict):
#         keyword = list(rule.keys())[0]
#         attributes = list(rule.values())[0]
#
#         elif keyword == "exists":
#             if not isinstance(attributes, bool):
#                 raise SNSInvalidParameter(
#                     "Invalid parameter: FilterPolicy: exists match pattern must be either true or false."
#                 )
#             continue
#         elif keyword == "numeric":
#             # TODO: All of the exceptions listed below contain column pointing where the error is (in AWS response)
#             # Example: 'Value of < must be numeric\n at [Source: (String)"{"price":[{"numeric":["<","100"]}]}"; line: 1, column: 28]'
#             # While it probably can be implemented, it doesn't feel as important as the general parameter checking
#
#             attributes_copy = attributes[:]
#             if not attributes_copy:
#                 raise SNSInvalidParameter(
#                     "Invalid parameter: Attributes Reason: FilterPolicy: Invalid member in numeric match: ]\n at ..."
#                 )
#
#             operator = attributes_copy.pop(0)
#
#             if not isinstance(operator, str):
#                 raise SNSInvalidParameter(
#                     f"Invalid parameter: Attributes Reason: FilterPolicy: Invalid member in numeric match: {(str(operator))}\n at ..."
#                 )
#
#             if operator not in ("<", "<=", "=", ">", ">="):
#                 raise SNSInvalidParameter(
#                     f"Invalid parameter: Attributes Reason: FilterPolicy: Unrecognized numeric range operator: {(str(operator))}\n at ..."
#                 )
#
#             try:
#                 value = attributes_copy.pop(0)
#             except IndexError:
#                 value = None
#
#             if value is None or not isinstance(value, (int, float)):
#                 raise SNSInvalidParameter(
#                     f"Invalid parameter: Attributes Reason: FilterPolicy: Value of {(str(operator))} must be numeric\n at ..."
#                 )
#
#             if not attributes_copy:
#                 continue
#
#             if operator not in (">", ">="):
#                 raise SNSInvalidParameter(
#                     "Invalid parameter: Attributes Reason: FilterPolicy: Too many elements in numeric expression\n at ..."
#                 )
#
#             second_operator = attributes_copy.pop(0)
#
#             if second_operator not in ("<", "<="):
#                 raise SNSInvalidParameter(
#                     f"Invalid parameter: Attributes Reason: FilterPolicy: Bad numeric range operator: {(str(second_operator))}\n at ..."
#                 )
#
#             try:
#                 second_value = attributes_copy.pop(0)
#             except IndexError:
#                 second_value = None
#
#             if second_value is None or not isinstance(
#                     second_value, (int, float)
#             ):
#                 raise SNSInvalidParameter(
#                     f"Invalid parameter: Attributes Reason: FilterPolicy: Value of {(str(second_operator))} must be numeric\n at ..."
#                 )
#
#             if second_value <= value:
#                 raise SNSInvalidParameter(
#                     "Invalid parameter: Attributes Reason: FilterPolicy: Bottom must be less than top\n at ..."
#                 )
#
#             continue
#         elif keyword in ["prefix", "suffix"]:
#             continue
#         else:
#             raise SNSInvalidParameter(
#                 f"Invalid parameter: FilterPolicy: Unrecognized match type {keyword}"
#             )
#
#         raise SNSInvalidParameter(
#             "Invalid parameter: FilterPolicy: Match value must be String, number, true, false, or null"
#         )
#
#
# def _validate_filter_policy(self, value: t.Any, scope: str) -> None:
#     # combinations = 1
#
#     # def aggregate_rules(filter_policy: dict[str, t.Any], depth: int = 1, combinations: int = 1) -> tuple[list[list[t.Any]], int]:
#     #     """
#     #     This method evaluate the filter policy recursively, and returns only a list of lists of rules.
#     #     It also calculates the combinations of rules, calculated depending on the nesting of the rules.
#     #     Example:
#     #     nested_filter_policy = {
#     #         "key_a": {
#     #             "key_b": {
#     #                 "key_c": ["value_one", "value_two", "value_three", "value_four"]
#     #             }
#     #         },
#     #         "key_d": {
#     #             "key_e": ["value_one", "value_two", "value_three"]
#     #         }
#     #     }
#     #     This function then iterates on the values of the top level keys of the filter policy: ("key_a", "key_d")
#     #     If the iterated value is not a list, it means it is a nested property. If the scope is `MessageBody`, it is
#     #     allowed, we call this method on the value, adding a level to the depth to keep track on how deep the key is.
#     #     If the value is a list, it means it contains rules: we will append this list of rules in _rules, and
#     #     calculate the combinations it adds.
#     #     For the example filter policy containing nested properties, we calculate it this way
#     #     The first array has four values in a three-level nested key, and the second has three values in a two-level
#     #     nested key. 3 x 4 x 2 x 3 = 72
#     #     The return value would be:
#     #     [["value_one", "value_two", "value_three", "value_four"], ["value_one", "value_two", "value_three"]]
#     #     It allows us to later iterate of the list of rules in an easy way, to verify its conditions.
#     #
#     #     :param filter_policy: a dict, starting at the FilterPolicy
#     #     :param depth: the depth/level of the rules we are evaluating
#     #     :param combinations: current numbers of combinations
#     #     :return: a list of lists of rules
#     #     """
#     #     # nonlocal combinations
#     #     _rules = []
#     #     for key, _value in filter_policy.items():
#     #         if isinstance(_value, dict):
#     #             if scope == "MessageBody":
#     #                 # From AWS docs: "unlike attribute-based policies, payload-based policies support property nesting."
#     #                 sub_rules, _ = aggregate_rules(_value, depth=depth + 1)
#     #                 _rules.extend(sub_rules)
#     #             else:
#     #                 raise SNSInvalidParameter(
#     #                     "Invalid parameter: Filter policy scope MessageAttributes does not support nested filter policy"
#     #                 )
#     #         elif isinstance(_value, list):
#     #             if key == "$or":
#     #                 for val in _value:
#     #                     sub_rules, _ = aggregate_rules(val, depth=depth + 1)
#     #                     _rules.extend(sub_rules)
#     #             else:
#     #                 _rules.append(_value)
#     #             combinations = combinations * len(_value) * depth
#     #         else:
#     #             raise SNSInvalidParameter(
#     #                 f'Invalid parameter: FilterPolicy: "{key}" must be an object or an array'
#     #             )
#     #     return _rules, combinations
#
#     # # A filter policy can have a maximum of five attribute names. For a nested policy, only parent keys are counted.
#     if len(value.values()) > 5:
#         raise SNSInvalidParameter(
#             "Invalid parameter: FilterPolicy: Filter policy can not have more than 5 keys"
#         )
#
#     aggregated_rules = aggregate_rules(value)
#     # For the complexity of the filter policy, the total combination of values must not exceed 150.
#     # https://docs.aws.amazon.com/sns/latest/dg/subscription-filter-policy-constraints.html
#     if combinations > 150:
#         raise SNSInvalidParameter(
#             "Invalid parameter: FilterPolicy: Filter policy is too complex"
#         )
#
#     for rules in aggregated_rules:
#         for rule in rules:
#             if rule is None:
#                 continue
#             if isinstance(rule, str):
#                 continue
#             if isinstance(rule, bool):
#                 continue
#             if isinstance(rule, (int, float)):
#                 if rule <= -1000000000 or rule >= 1000000000:
#                     raise InternalError("Unknown")
#                 continue
#             if isinstance(rule, dict):
#                 keyword = list(rule.keys())[0]
#                 attributes = list(rule.values())[0]
#                 if keyword in ["anything-but", "equals-ignore-case"]:
#                     continue
#                 elif keyword == "exists":
#                     if not isinstance(attributes, bool):
#                         raise SNSInvalidParameter(
#                             "Invalid parameter: FilterPolicy: exists match pattern must be either true or false."
#                         )
#                     continue
#                 elif keyword == "numeric":
#                     # TODO: All of the exceptions listed below contain column pointing where the error is (in AWS response)
#                     # Example: 'Value of < must be numeric\n at [Source: (String)"{"price":[{"numeric":["<","100"]}]}"; line: 1, column: 28]'
#                     # While it probably can be implemented, it doesn't feel as important as the general parameter checking
#
#                     attributes_copy = attributes[:]
#                     if not attributes_copy:
#                         raise SNSInvalidParameter(
#                             "Invalid parameter: Attributes Reason: FilterPolicy: Invalid member in numeric match: ]\n at ..."
#                         )
#
#                     operator = attributes_copy.pop(0)
#
#                     if not isinstance(operator, str):
#                         raise SNSInvalidParameter(
#                             f"Invalid parameter: Attributes Reason: FilterPolicy: Invalid member in numeric match: {(str(operator))}\n at ..."
#                         )
#
#                     if operator not in ("<", "<=", "=", ">", ">="):
#                         raise SNSInvalidParameter(
#                             f"Invalid parameter: Attributes Reason: FilterPolicy: Unrecognized numeric range operator: {(str(operator))}\n at ..."
#                         )
#
#                     try:
#                         value = attributes_copy.pop(0)
#                     except IndexError:
#                         value = None
#
#                     if value is None or not isinstance(value, (int, float)):
#                         raise SNSInvalidParameter(
#                             f"Invalid parameter: Attributes Reason: FilterPolicy: Value of {(str(operator))} must be numeric\n at ..."
#                         )
#
#                     if not attributes_copy:
#                         continue
#
#                     if operator not in (">", ">="):
#                         raise SNSInvalidParameter(
#                             "Invalid parameter: Attributes Reason: FilterPolicy: Too many elements in numeric expression\n at ..."
#                         )
#
#                     second_operator = attributes_copy.pop(0)
#
#                     if second_operator not in ("<", "<="):
#                         raise SNSInvalidParameter(
#                             f"Invalid parameter: Attributes Reason: FilterPolicy: Bad numeric range operator: {(str(second_operator))}\n at ..."
#                         )
#
#                     try:
#                         second_value = attributes_copy.pop(0)
#                     except IndexError:
#                         second_value = None
#
#                     if second_value is None or not isinstance(
#                             second_value, (int, float)
#                     ):
#                         raise SNSInvalidParameter(
#                             f"Invalid parameter: Attributes Reason: FilterPolicy: Value of {(str(second_operator))} must be numeric\n at ..."
#                         )
#
#                     if second_value <= value:
#                         raise SNSInvalidParameter(
#                             "Invalid parameter: Attributes Reason: FilterPolicy: Bottom must be less than top\n at ..."
#                         )
#
#                     continue
#                 elif keyword in ["prefix", "suffix"]:
#                     continue
#                 else:
#                     raise SNSInvalidParameter(
#                         f"Invalid parameter: FilterPolicy: Unrecognized match type {keyword}"
#                     )
#
#             raise SNSInvalidParameter(
#                 "Invalid parameter: FilterPolicy: Match value must be String, number, true, false, or null"
#             )
