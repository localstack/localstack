from abc import ABC

from localstack.aws.api.swf import SwfApi


class SWFProvider(SwfApi, ABC):
    pass
