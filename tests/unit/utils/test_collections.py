from typing import Optional, TypedDict

from localstack.utils.collections import select_from_typed_dict


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
