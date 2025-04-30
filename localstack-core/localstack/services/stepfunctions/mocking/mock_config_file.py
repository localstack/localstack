import logging
import os
from functools import lru_cache
from json import JSONDecodeError
from typing import Any, Dict, Final, Optional

from pydantic import BaseModel, RootModel, ValidationError, model_validator

from localstack import config

LOG = logging.getLogger(__name__)

_RETURN_KEY: Final[str] = "Return"
_THROW_KEY: Final[str] = "Throw"


class RawReturnResponse(RootModel[Any]):
    """
    Represents a return response.
    Accepts any fields.
    """

    model_config = {"frozen": True}


class RawThrowResponse(BaseModel):
    """
    Represents an error response.
    Both 'Error' and 'Cause' are required.
    """

    model_config = {"frozen": True}

    Error: str
    Cause: str


class RawResponseModel(BaseModel):
    """
    A response step must include exactly one of:
      - 'Return': a ReturnResponse object.
      - 'Throw': a ThrowResponse object.
    """

    model_config = {"frozen": True}

    Return: Optional[RawReturnResponse] = None
    Throw: Optional[RawThrowResponse] = None

    @model_validator(mode="before")
    def validate_response(cls, data: dict) -> dict:
        if _RETURN_KEY in data and _THROW_KEY in data:
            raise ValueError(f"Response cannot contain both '{_RETURN_KEY}' and '{_THROW_KEY}'")
        if _RETURN_KEY not in data and _THROW_KEY not in data:
            raise ValueError(f"Response must contain one of '{_RETURN_KEY}' or '{_THROW_KEY}'")
        return data


class RawTestCase(RootModel[Dict[str, str]]):
    """
    Represents an individual test case.
    The keys are state names (e.g., 'LambdaState', 'SQSState')
    and the values are the names of the mocked response configurations.
    """

    model_config = {"frozen": True}


class RawStateMachine(BaseModel):
    """
    Represents a state machine configuration containing multiple test cases.
    """

    model_config = {"frozen": True}

    TestCases: Dict[str, RawTestCase]


class RawMockConfig(BaseModel):
    """
    The root configuration that contains:
      - StateMachines: mapping state machine names to their configuration.
      - MockedResponses: mapping response configuration names to response steps.
          Each response step is keyed (e.g. "0", "1-2") and maps to a ResponseModel.
    """

    model_config = {"frozen": True}

    StateMachines: Dict[str, RawStateMachine]
    MockedResponses: Dict[str, Dict[str, RawResponseModel]]


@lru_cache(maxsize=1)
def _read_sfn_raw_mock_config(file_path: str, modified_epoch: int) -> Optional[RawMockConfig]:  # noqa
    """
    Load and cache the Step Functions mock configuration from a JSON file.

    This function is memoized using `functools.lru_cache` to avoid re-reading the file
    from disk unless it has changed. The `modified_epoch` parameter is used solely to
    trigger cache invalidation when the file is updated. If either the file path or the
    modified timestamp changes, the cached result is discarded and the file is reloaded.

    Parameters:
        file_path (str):
            The absolute path to the JSON configuration file.

        modified_epoch (int):
            The last modified time of the file, in epoch seconds. This value is used
            as part of the cache key to ensure the cache is refreshed when the file is updated.

    Returns:
        Optional[dict]:
            The parsed configuration as a dictionary if the file is successfully loaded,
            or `None` if an error occurs during reading or parsing.

    Notes:
        - The `modified_epoch` argument is not used inside the function logic, but is
          necessary to ensure cache correctness via `lru_cache`.
        - Logging is used to capture warnings if file access or parsing fails.
    """
    try:
        with open(file_path, "r") as df:
            mock_config_str = df.read()
        mock_config: RawMockConfig = RawMockConfig.model_validate_json(mock_config_str)
        return mock_config
    except (OSError, IOError) as file_error:
        LOG.error("Failed to open mock configuration file '%s'. Error: %s", file_path, file_error)
        return None
    except ValidationError as validation_error:
        errors = validation_error.errors()
        if not errors:
            # No detailed errors provided by Pydantic
            LOG.error(
                "Validation failed for mock configuration file at '%s'. "
                "The file must contain a valid mock configuration.",
                file_path,
            )
        else:
            for err in errors:
                location = ".".join(str(loc) for loc in err["loc"])
                message = err["msg"]
                error_type = err["type"]
                LOG.error(
                    "Mock configuration file error at '%s': %s (%s)",
                    location,
                    message,
                    error_type,
                )
        # TODO: add tests to ensure the hot-reloading of the mock configuration
        #  file works as expected, and inform the user with the info below:
        # LOG.info(
        #     "Changes to the mock configuration file will be applied at the "
        #     "next mock execution without requiring a LocalStack restart."
        # )
        return None
    except JSONDecodeError as json_error:
        LOG.error(
            "Malformed JSON in mock configuration file at '%s'. Error: %s",
            file_path,
            json_error,
        )
        # TODO: add tests to ensure the hot-reloading of the mock configuration
        #  file works as expected, and inform the user with the info below:
        # LOG.info(
        #     "Changes to the mock configuration file will be applied at the "
        #     "next mock execution without requiring a LocalStack restart."
        # )
        return None


def _load_sfn_raw_mock_config() -> Optional[RawMockConfig]:
    configuration_file_path = config.SFN_MOCK_CONFIG
    if not configuration_file_path:
        return None

    try:
        modified_time = int(os.path.getmtime(configuration_file_path))
    except Exception as ex:
        LOG.warning(
            "Unable to access the step functions mock configuration file at '%s' due to %s",
            configuration_file_path,
            ex,
        )
        return None

    mock_config = _read_sfn_raw_mock_config(configuration_file_path, modified_time)
    return mock_config
