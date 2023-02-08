from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_list import (
    FunctionArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.array import (
    states_function_array,
    states_function_array_contains,
    states_function_array_partition,
    states_function_array_range,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function import (
    StatesFunction,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function_format import (
    StatesFunctionFormat,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function_json_to_string import (
    StatesFunctionJsonToString,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function_string_to_json import (
    StatesFunctionStringToJson,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function_uuid import (
    StatesFunctionUUID,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_fuinction_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)


# TODO: use reflection on StatesFunctionNameType values.
class StatesFunctionFactory:
    @staticmethod
    def from_name(func_name: StatesFunctionName, arg_list: FunctionArgumentList) -> StatesFunction:
        match func_name.function_type:
            # Array.
            case StatesFunctionNameType.Array:
                return states_function_array.StatesFunctionArray(arg_list=arg_list)
            case StatesFunctionNameType.ArrayPartition:
                return states_function_array_partition.StatesFunctionArrayPartition(
                    arg_list=arg_list
                )
            case StatesFunctionNameType.ArrayContains:
                return states_function_array_contains.StatesFunctionArrayContains(arg_list=arg_list)
            case StatesFunctionNameType.ArrayRange:
                return states_function_array_range.StatesFunctionArrayRange(arg_list=arg_list)
            #
            case StatesFunctionNameType.Format:
                return StatesFunctionFormat(arg_list=arg_list)
            case StatesFunctionNameType.JsonToString:
                return StatesFunctionJsonToString(arg_list=arg_list)
            case StatesFunctionNameType.StringToJson:
                return StatesFunctionStringToJson(arg_list=arg_list)
            case StatesFunctionNameType.UUID:
                return StatesFunctionUUID(arg_list=arg_list)
            #
            case unsupported:
                raise NotImplementedError(unsupported)  # noqa
