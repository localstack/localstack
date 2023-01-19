from localstack.services.stepfunctions.asl.component.intrinsic.argument.function_argument_list import (
    FunctionArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function import (
    StatesFunction,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function_array import (
    StatesFunctionArray,
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
            case StatesFunctionNameType.Format:
                return StatesFunctionFormat(arg_list=arg_list)
            case StatesFunctionNameType.Array:
                return StatesFunctionArray(arg_list=arg_list)
            case StatesFunctionNameType.JsonToString:
                return StatesFunctionJsonToString(arg_list=arg_list)
            case StatesFunctionNameType.StringToJson:
                return StatesFunctionStringToJson(arg_list=arg_list)
            case StatesFunctionNameType.UUID:
                return StatesFunctionUUID(arg_list=arg_list)
            case unsupported:
                raise NotImplementedError(unsupported)  # noqa
