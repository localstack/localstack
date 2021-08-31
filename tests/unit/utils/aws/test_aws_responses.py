import xml.etree.ElementTree as ET

import pytest

from localstack.utils.aws.aws_responses import to_xml

result_raw = {
    "DescribeChangeSetResult": {
        # ...
        "Changes": [
            {
                "ResourceChange": {
                    "Replacement": False,
                    "Scope": ["Tags"],
                },
                "Type": "Resource",
            }
        ]
    }
}

result_raw_none_element = {"a": {"b": None}}

result_raw_empty_list = {"a": {"b": []}}
result_raw_multiple_members = {"a": {"b": ["c", "d"]}}


@pytest.mark.parametrize(
    "test_input,included",
    [
        (
            result_raw,
            "<member><ResourceChange><Replacement>False</Replacement><Scope><member>Tags</member></Scope></ResourceChange><Type>Resource</Type></member>",
        ),
        (result_raw_none_element, "<b />"),
        (result_raw_empty_list, "<b />"),
        (result_raw_multiple_members, "<b><member>c</member><member>d</member></b>"),
    ],
)
def test_to_xml(test_input, included):
    result = to_xml(test_input)
    result_str = str(ET.tostring(result, short_empty_elements=True))
    assert included in result_str


@pytest.mark.parametrize(
    "test_input", [lambda: None, lambda: [], lambda: "", lambda: 0]
)  # direct literals here trip up pytest
def test_to_xml_raise_error_simpleinputs(test_input):
    with pytest.raises(Exception):
        to_xml(test_input())


class SomeClass:
    pass


result_raw_class_value = {"a": {"b": SomeClass()}}
multiple_root = {"a": "b", "c": "d"}
empty_dict = {}


@pytest.mark.parametrize("test_input", [multiple_root, empty_dict, result_raw_class_value])
def test_to_xml_raise_error_malformeddict(test_input):
    with pytest.raises(Exception):
        to_xml(test_input)
