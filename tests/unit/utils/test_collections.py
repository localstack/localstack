from typing import Optional, TypedDict

from localstack.utils.collections import HashableJsonDict, HashableList, select_from_typed_dict


class MyTypeDict(TypedDict):
    key_one: str
    key_optional: Optional[str]


def test_select_from_typed_dict():
    d = {"key_one": "key_one", "key_optional": "key_optional"}
    result = select_from_typed_dict(typed_dict=MyTypeDict, obj=d)
    assert result == d
    d["key_too_much"] = "key_too_much"
    result = select_from_typed_dict(typed_dict=MyTypeDict, obj=d)
    assert result == {"key_one": "key_one", "key_optional": "key_optional"}
    del d["key_one"]
    result = select_from_typed_dict(typed_dict=MyTypeDict, obj=d)
    assert result == {"key_optional": "key_optional"}


def test_hashable_dict():
    d1 = HashableJsonDict({"a": ["b"], "c": 1})
    d2 = HashableJsonDict({"a": "b"})
    d3 = HashableJsonDict({"c": 1, "a": ["b"]})
    d4 = HashableJsonDict({})

    assert len({d1, d2, d3}) == 2
    assert {d1, d2, d3} == {d1, d2} == {d2, d3}
    assert {d1, d3} == {d3, d1}
    assert {d1, d1} == {d3, d3}
    assert {d1, d2, d3} != {d1}
    assert {d1, d2, d3} != {d2}
    assert {d1, d2, d3} != {d1, d3}
    assert {d4, d4} == {d4}


def test_hashable_list():
    l1 = HashableList([1, 2])
    l2 = HashableList([1, 2])
    l3 = HashableList([1, 2, 3])

    assert {l1, l2} == {l1} == {l2, l2}
    assert {l1, l3} == {l2, l3}
    assert {l1, l2} != {l3}
