from typing import Optional, TypedDict, Union

import pytest

from localstack.utils.collections import (
    HashableJsonDict,
    HashableList,
    ImmutableDict,
    ImmutableList,
    convert_to_typed_dict,
    select_from_typed_dict,
)


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

    d = {"key_one": "key_one", "key_optional": None}
    result = select_from_typed_dict(typed_dict=MyTypeDict, obj=d, filter=True)
    assert result == {"key_one": "key_one"}

    d = {"key_one": "key_one", "key_optional": {}}
    result = select_from_typed_dict(typed_dict=MyTypeDict, obj=d, filter=True)
    assert result == {"key_one": "key_one"}


def test_immutable_dict():
    d1 = ImmutableDict({"a": ["b"], "c": 1})

    assert dict(d1) == {"a": ["b"], "c": 1}
    assert {k for k in d1} == {"a", "c"}
    assert d1["a"] == ["b"]
    assert d1["c"] == 1
    assert len(d1) == 2

    assert "a" in d1
    assert "z" not in d1

    with pytest.raises(Exception) as exc:
        d1["foo"] = "bar"
    exc.match("does not support item assignment")


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

    with pytest.raises(Exception) as exc:
        d1["foo"] = "bar"
    exc.match("does not support item assignment")


def test_immutable_list():
    l1 = ImmutableList([1, 2, 3])

    assert list(l1) == [1, 2, 3]
    assert l1[0] == 1
    assert l1[1] == 2
    assert list(l1) == [1, 2, 3]
    assert len(l1) == 3

    assert 2 in l1
    assert 99 not in l1
    assert l1.count(1) == 1
    assert l1.count(99) == 0
    assert l1.index(2) == 1
    assert list(reversed(l1)) == [3, 2, 1]

    with pytest.raises(Exception) as exc:
        l1[0] = "foo"
    exc.match("does not support item assignment")
    with pytest.raises(Exception) as exc:
        l1.append("foo")


def test_hashable_list():
    l1 = HashableList([1, 2])
    l2 = HashableList([1, 2])
    l3 = HashableList([1, 2, 3])

    assert {l1, l2} == {l1} == {l2, l2}
    assert {l1, l3} == {l2, l3}
    assert {l1, l2} != {l3}

    with pytest.raises(Exception) as exc:
        l1[0] = "foo"
    exc.match("does not support item assignment")


def test_convert_to_typed_dict():
    class TestTypedDict(TypedDict):
        str_member: str
        int_member: int
        dict_member: dict

    test_dict = {"str_member": 1, "int_member": "1", "dict_member": {"inner_member": 1}}

    result = convert_to_typed_dict(TestTypedDict, test_dict)
    assert isinstance(result, dict)
    assert result["str_member"] == "1"
    assert result["int_member"] == 1
    assert result["dict_member"] == {"inner_member": 1}


def test_convert_to_typed_dict_with_union():
    class TestTypedDict(TypedDict):
        union_member: Union[str, int]

    test_dict = {"union_member": 1}

    result = convert_to_typed_dict(TestTypedDict, test_dict)
    assert isinstance(result, dict)
    assert result["union_member"] == "1"


def test_convert_to_typed_dict_with_optional():
    class TestTypedDict(TypedDict):
        optional_member: Optional[str]

    test_dict = {"optional_member": 1}

    result = convert_to_typed_dict(TestTypedDict, test_dict)
    assert isinstance(result, dict)
    assert result["optional_member"] == "1"


def test_convert_to_typed_dict_with_strict_mode():
    class ClassWithoutValueConstructor:
        pass

    class TestTypedDict(TypedDict):
        non_convertable: ClassWithoutValueConstructor

    test_dict = {"non_convertable": ClassWithoutValueConstructor()}

    # ensure the strict conversion fails
    with pytest.raises(TypeError):
        convert_to_typed_dict(TestTypedDict, test_dict, strict=True)

    # ensure the non-strict conversion contains the original values
    result = convert_to_typed_dict(TestTypedDict, test_dict)
    assert test_dict == result


def test_convert_to_typed_dict_with_typed_subdict():
    class InnerTypedDict(TypedDict):
        str_member: str

    class TestTypedDict(TypedDict):
        subdict: InnerTypedDict

    test_dict = {"subdict": {"str_member": 1}}

    result = convert_to_typed_dict(TestTypedDict, test_dict)
    assert isinstance(result, dict)
    assert result["subdict"] == {"str_member": "1"}
