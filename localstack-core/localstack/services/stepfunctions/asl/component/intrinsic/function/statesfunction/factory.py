from localstack.services.stepfunctions.asl.component.intrinsic.argument.argument import ArgumentList
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.array import (
    array,
    array_contains,
    array_get_item,
    array_length,
    array_partition,
    array_range,
    array_unique,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.encoding_decoding import (
    base_64_decode,
    base_64_encode,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.generic import (
    string_format,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.hash_calculations import (
    hash_func,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.json_manipulation import (
    json_merge,
    json_to_string,
    string_to_json,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.math_operations import (
    math_add,
    math_random,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function import (
    StatesFunction,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.string_operations import (
    string_split,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.unique_id_generation import (
    uuid,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_function_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)


# TODO: could use reflection on StatesFunctionNameType values.
class StatesFunctionFactory:
    @staticmethod
    def from_name(func_name: StatesFunctionName, argument_list: ArgumentList) -> StatesFunction:
        match func_name.function_type:
            # Array.
            case StatesFunctionNameType.Array:
                return array.Array(argument_list=argument_list)
            case StatesFunctionNameType.ArrayPartition:
                return array_partition.ArrayPartition(argument_list=argument_list)
            case StatesFunctionNameType.ArrayContains:
                return array_contains.ArrayContains(argument_list=argument_list)
            case StatesFunctionNameType.ArrayRange:
                return array_range.ArrayRange(argument_list=argument_list)
            case StatesFunctionNameType.ArrayGetItem:
                return array_get_item.ArrayGetItem(argument_list=argument_list)
            case StatesFunctionNameType.ArrayLength:
                return array_length.ArrayLength(argument_list=argument_list)
            case StatesFunctionNameType.ArrayUnique:
                return array_unique.ArrayUnique(argument_list=argument_list)

            # JSON Manipulation
            case StatesFunctionNameType.JsonToString:
                return json_to_string.JsonToString(argument_list=argument_list)
            case StatesFunctionNameType.StringToJson:
                return string_to_json.StringToJson(argument_list=argument_list)
            case StatesFunctionNameType.JsonMerge:
                return json_merge.JsonMerge(argument_list=argument_list)

            # Unique Id Generation.
            case StatesFunctionNameType.UUID:
                return uuid.UUID(argument_list=argument_list)

            # String Operations.
            case StatesFunctionNameType.StringSplit:
                return string_split.StringSplit(argument_list=argument_list)

            # Hash Calculations.
            case StatesFunctionNameType.Hash:
                return hash_func.HashFunc(argument_list=argument_list)

            # Encoding and Decoding.
            case StatesFunctionNameType.Base64Encode:
                return base_64_encode.Base64Encode(argument_list=argument_list)
            case StatesFunctionNameType.Base64Decode:
                return base_64_decode.Base64Decode(argument_list=argument_list)

            # Math Operations.
            case StatesFunctionNameType.MathRandom:
                return math_random.MathRandom(argument_list=argument_list)
            case StatesFunctionNameType.MathAdd:
                return math_add.MathAdd(argument_list=argument_list)

            # Generic.
            case StatesFunctionNameType.Format:
                return string_format.StringFormat(argument_list=argument_list)

            # Unsupported.
            case unsupported:
                raise NotImplementedError(unsupported)  # noqa
