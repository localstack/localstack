import abc
from typing import Any, Final, Optional

from localstack.services.stepfunctions.mocking.mock_config_file import (
    RawMockConfig,
    RawResponseModel,
    RawTestCase,
    _load_sfn_raw_mock_config,
)


class MockedResponse(abc.ABC):
    range_start: Final[int]
    range_end: Final[int]

    def __init__(self, range_start: int, range_end: int):
        super().__init__()
        if range_start < 0 or range_end < 0:
            raise ValueError(
                f"Invalid range: both '{range_start}' and '{range_end}' must be positive integers."
            )
        if range_start != range_end and range_end < range_start + 1:
            raise ValueError(
                f"Invalid range: values must be equal or '{range_start}' "
                f"must be at least one greater than '{range_end}'."
            )
        self.range_start = range_start
        self.range_end = range_end


class MockedResponseReturn(MockedResponse):
    payload: Final[Any]

    def __init__(self, range_start: int, range_end: int, payload: Any):
        super().__init__(range_start=range_start, range_end=range_end)
        self.payload = payload


class MockedResponseThrow(MockedResponse):
    error: Final[str]
    cause: Final[str]

    def __init__(self, range_start: int, range_end: int, error: str, cause: str):
        super().__init__(range_start=range_start, range_end=range_end)
        self.error = error
        self.cause = cause


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
        last_range_end: int = -1
        mocked_responses_sorted = sorted(mocked_responses, key=lambda mr: mr.range_start)
        for mocked_response in mocked_responses_sorted:
            if not mocked_response.range_start - last_range_end == 1:
                raise RuntimeError(
                    f"Inconsistent event numbering detected for state '{state_name}': "
                    f"the previous mocked response ended at event '{last_range_end}' "
                    f"while the next response '{mocked_response_name}' "
                    f"starts at event '{mocked_response.range_start}'. "
                    "Mock responses must be consecutively numbered. "
                    f"Expected the next response to begin at event {last_range_end + 1}."
                )
            repeats = mocked_response.range_end - mocked_response.range_start + 1
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
    raw_response_models: Optional[dict[str, RawResponseModel]] = (
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
