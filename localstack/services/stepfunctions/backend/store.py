from collections import OrderedDict
from typing import Final

from localstack.services.stepfunctions.backend.execution import Execution
from localstack.services.stepfunctions.backend.state_machine import StateMachine
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class SFNStore(BaseStore):
    sm_by_arn: dict[str, StateMachine] = LocalAttribute(default=dict)
    execs_by_exec_arn: dict[str, Execution] = LocalAttribute(
        default=OrderedDict
    )  # TODO: when snapshot to pods stop execution(?)


sfn_stores: Final[AccountRegionBundle] = AccountRegionBundle("stepfunctions", SFNStore)
