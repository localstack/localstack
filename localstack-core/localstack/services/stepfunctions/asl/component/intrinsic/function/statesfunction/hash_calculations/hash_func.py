import hashlib
from typing import Final

from localstack.services.stepfunctions.asl.component.intrinsic.argument.argument import (
    ArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.hash_calculations.hash_algorithm import (
    HashAlgorithm,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function import (
    StatesFunction,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_function_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class HashFunc(StatesFunction):
    MAX_INPUT_CHAR_LEN: Final[int] = 10_000

    def __init__(self, argument_list: ArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.Hash),
            argument_list=argument_list,
        )
        if argument_list.size != 2:
            raise ValueError(
                f"Expected 2 arguments for function type '{type(self)}', but got: '{argument_list}'."
            )

    @staticmethod
    def _hash_inp_with_alg(inp: str, alg: HashAlgorithm) -> str:
        inp_enc = inp.encode()
        hash_inp = None
        match alg:
            case HashAlgorithm.MD5:
                hash_inp = hashlib.md5(inp_enc)
            case HashAlgorithm.SHA_1:
                hash_inp = hashlib.sha1(inp_enc)
            case HashAlgorithm.SHA_256:
                hash_inp = hashlib.sha256(inp_enc)
            case HashAlgorithm.SHA_384:
                hash_inp = hashlib.sha384(inp_enc)
            case HashAlgorithm.SHA_512:
                hash_inp = hashlib.sha512(inp_enc)
        hash_value: str = hash_inp.hexdigest()
        return hash_value

    def _eval_body(self, env: Environment) -> None:
        self.argument_list.eval(env=env)
        args = env.stack.pop()

        algorithm = args.pop()
        try:
            hash_algorithm = HashAlgorithm(algorithm)
        except Exception:
            raise ValueError(f"Unknown hash function '{algorithm}'.")

        input_data = args.pop()
        if not isinstance(input_data, str):
            raise TypeError(
                f"Expected string type as input data for function type '{type(self)}', but got: '{input_data}'."
            )

        if len(input_data) > self.MAX_INPUT_CHAR_LEN:
            raise ValueError(
                f"Maximum character input length for  for function type '{type(self)}' "
                f"is '{self.MAX_INPUT_CHAR_LEN}', but got '{len(input_data)}'."
            )

        res = self._hash_inp_with_alg(input_data, hash_algorithm)
        env.stack.append(res)
