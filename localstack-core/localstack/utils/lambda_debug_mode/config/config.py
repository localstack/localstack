from __future__ import annotations

import abc
from typing import Optional

from localstack.aws.api.lambda_ import Arn


class LambdaDebugModeConfig(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def from_raw(cls, raw_config: dict): ...

    @abc.abstractmethod
    def lambda_is_enforce_timeouts_for(self, lambda_arn: Arn) -> bool: ...

    @abc.abstractmethod
    def lambda_debug_client_port_for(self, lambda_arn: Arn) -> Optional[int]: ...

    @abc.abstractmethod
    def lambda_debugger_port_for(self, lambda_arn: Arn) -> Optional[int]: ...
