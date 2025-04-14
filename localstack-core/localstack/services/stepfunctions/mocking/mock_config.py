import logging
import os
from functools import lru_cache
from typing import Dict, Final, Optional

from pydantic import BaseModel, RootModel, model_validator

from localstack import config
from localstack.services.stepfunctions.mocking.components import (
    MockedResponse,
    MockedResponseReturn,
    MockedResponseThrow,
)

LOG = logging.getLogger(__name__)

_RETURN_KEY: Final[str] = "Return"
_THROW_KEY: Final[str] = "Throw"


class RawReturnResponse(BaseModel):
    """
    Represents a return response.
    Accepts any fields.
    """

    model_config = {"extra": "allow", "frozen": True}


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


class StateMockedResponses:
    state_name: Final[str]
    mocked_response_name: Final[str]
    mocked_responses: Final[list[MockedResponse]]

    def __init__(
        self, state_name: str, mocked_response_name: str, mocked_responses: list[MockedResponse]
    ):
        self.state_name = state_name
        self.mocked_response_name = mocked_response_name
        self.mocked_responses = list()
        last_range_end: int = 0
        mocked_responses_sorted = sorted(mocked_responses, key=lambda mr: mr.range_start)
        for mocked_response in mocked_responses_sorted:
            if not mocked_response.range_start - last_range_end == 0:
                raise RuntimeError(
                    f"Inconsistent event numbering detected for state '{state_name}': "
                    f"the previous mocked response ended at event '{last_range_end}' "
                    f"while the next response '{mocked_response_name}' "
                    f"starts at event '{mocked_response.range_start}'. "
                    "Mock responses must be consecutively numbered. "
                    f"Expected the next response to begin at event {last_range_end + 1}."
                )
            repeats = mocked_response.range_start - mocked_response.range_end + 1
            self.mocked_responses.extend([mocked_response] * repeats)
            last_range_end = mocked_response.range_end


class MockTestCase:
    state_machine_name: Final[str]
    test_case_name: Final[str]
    state_mocked_responses: Final[dict[str, StateMockedResponses]]

    def __init__(
        self,
        state_machine_name: str,
        test_case_name: str,
        state_mocked_responses_list: list[StateMockedResponses],
    ):
        self.state_machine_name = state_machine_name
        self.test_case_name = test_case_name
        self.state_mocked_responses = dict()
        for state_mocked_response in state_mocked_responses_list:
            state_name = state_mocked_response.state_name
            if state_name in self.state_mocked_responses:
                raise RuntimeError(
                    f"Duplicate definition of state '{state_name}' for test case '{test_case_name}'"
                )
            self.state_mocked_responses[state_name] = state_mocked_response


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
    except Exception as ex:
        LOG.warning(
            "Unable to load step functions mock configuration file at '%s' due to %s",
            file_path,
            ex,
        )
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


def _parse_mocked_response_range(string_definition: str) -> tuple[int, int]:
    definition_parts = string_definition.strip().split("-")
    if len(definition_parts) == 1:
        range_part = definition_parts[0]
        try:
            range_value = int(range_part)
            return range_value, range_value
        except Exception:
            raise RuntimeError(
                f"Unknown mocked response retry range value '{range_part}', not a valid integer"
            )
    elif len(definition_parts) == 2:
        range_part_start = definition_parts[0]
        range_part_end = definition_parts[1]
        try:
            return int(range_part_start), int(range_part_end)
        except Exception:
            raise RuntimeError(
                f"Unknown mocked response retry range value '{range_part_start}:{range_part_end}', "
                "not valid integer values"
            )
    else:
        raise RuntimeError(
            f"Unknown mocked response retry range definition '{string_definition}', "
            "range definition should consist of one integer (e.g. '0'), or a integer range (e.g. '1-2')'."
        )


def _mocked_response_from_raw(
    raw_response_model_range: str, raw_response_model: RawResponseModel
) -> MockedResponse:
    range_start, range_end = _parse_mocked_response_range(raw_response_model_range)
    if raw_response_model.Return:
        payload = raw_response_model.Return.model_dump()
        return MockedResponseReturn(range_start=range_start, range_end=range_end, payload=payload)
    throw_definition = raw_response_model.Throw
    return MockedResponseThrow(
        range_start=range_start,
        range_end=range_end,
        error=throw_definition.Error,
        cause=throw_definition.Cause,
    )


def _mocked_responses_from_raw(
    mocked_response_name: str, raw_mock_config: RawMockConfig
) -> list[MockedResponse]:
    raw_response_models: Optional[Dict[str, RawResponseModel]] = (
        raw_mock_config.MockedResponses.get(mocked_response_name)
    )
    if not raw_response_models:
        raise RuntimeError(
            f"No definitions for mocked response '{mocked_response_name}' in the mock configuration file."
        )
    mocked_responses: list[MockedResponse] = list()
    for raw_response_model_range, raw_response_model in raw_response_models.items():
        mocked_response: MockedResponse = _mocked_response_from_raw(
            raw_response_model_range=raw_response_model_range, raw_response_model=raw_response_model
        )
        mocked_responses.append(mocked_response)
    return mocked_responses


def _state_mocked_responses_from_raw(
    state_name: str, mocked_response_name: str, raw_mock_config: RawMockConfig
) -> StateMockedResponses:
    mocked_responses = _mocked_responses_from_raw(
        mocked_response_name=mocked_response_name, raw_mock_config=raw_mock_config
    )
    return StateMockedResponses(
        state_name=state_name,
        mocked_response_name=mocked_response_name,
        mocked_responses=mocked_responses,
    )


def _mock_test_case_from_raw(
    state_machine_name: str, test_case_name: str, raw_mock_config: RawMockConfig
) -> MockTestCase:
    state_machine = raw_mock_config.StateMachines.get(state_machine_name)
    if not state_machine:
        raise RuntimeError(
            f"No definitions for state machine '{state_machine_name}' in the mock configuration file."
        )
    test_case: RawTestCase = state_machine.TestCases.get(test_case_name)
    if not test_case:
        raise RuntimeError(
            f"No definitions for test case '{test_case_name}' and "
            f"state machine '{state_machine_name}' in the mock configuration file."
        )
    state_mocked_responses_list: list[StateMockedResponses] = list()
    for state_name, mocked_response_name in test_case.root.items():
        state_mocked_responses = _state_mocked_responses_from_raw(
            state_name=state_name,
            mocked_response_name=mocked_response_name,
            raw_mock_config=raw_mock_config,
        )
        state_mocked_responses_list.append(state_mocked_responses)
    return MockTestCase(
        state_machine_name=state_machine_name,
        test_case_name=test_case_name,
        state_mocked_responses_list=state_mocked_responses_list,
    )


def load_mock_test_case_for(state_machine_name: str, test_case_name: str) -> Optional[MockTestCase]:
    raw_mock_config: Optional[RawMockConfig] = _load_sfn_raw_mock_config()
    if raw_mock_config is None:
        return None
    mock_test_case: MockTestCase = _mock_test_case_from_raw(
        state_machine_name=state_machine_name,
        test_case_name=test_case_name,
        raw_mock_config=raw_mock_config,
    )
    return mock_test_case
