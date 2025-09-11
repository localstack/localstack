import pytest
from moto.core.exceptions import ServiceException

from localstack.aws.api import CommonServiceException
from localstack.services.moto import ServiceExceptionTranslator, get_dispatcher


def test_get_dispatcher_for_path_with_optional_slashes():
    assert get_dispatcher("route53", "/2013-04-01/hostedzone/BOR36Z3H458JKS9/rrset/")
    assert get_dispatcher("route53", "/2013-04-01/hostedzone/BOR36Z3H458JKS9/rrset")


def test_get_dispatcher_for_non_existing_path_raises_not_implemented():
    with pytest.raises(NotImplementedError):
        get_dispatcher("route53", "/non-existing")


def test_service_exception_translator_context_manager():
    class WeirdException(ServiceException):
        code = "WeirdErrorCode"

    # Ensure Moto ServiceExceptions are translated to ASF CommonServiceException
    with pytest.raises(CommonServiceException) as exc:
        with ServiceExceptionTranslator():
            raise WeirdException()
    assert exc.value.code == "WeirdErrorCode"

    # Ensure other exceptions are not affected
    with pytest.raises(RuntimeError):
        raise RuntimeError()

    with pytest.raises(RuntimeError):
        with ServiceExceptionTranslator():
            raise RuntimeError()
