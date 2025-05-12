from unittest import SkipTest

import pytest

from localstack.testing.aws.asf_utils import (
    check_provider_signature,
    collect_implemented_provider_operations,
)


@pytest.mark.parametrize(
    "sub_class,base_class,method_name",
    collect_implemented_provider_operations(),
)
def test_provider_signatures(sub_class: type, base_class: type, method_name: str):
    if "TranscribeApi" in str(base_class):
        raise SkipTest(
            "Transcribe Signatures are different on purpose, as optional args are marked as such"
        )
    check_provider_signature(sub_class, base_class, method_name)
