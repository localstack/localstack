from localstack.utils.strings import (
    key_value_pairs_to_dict,
    prepend_with_slash,
)


def test_prepend_with_slash():
    assert prepend_with_slash("hello") == "/hello"
    assert prepend_with_slash("/world") == "/world"
    assert prepend_with_slash("//world") == "//world"


def test_key_value_pairs_to_dict():
    assert key_value_pairs_to_dict("a=1,b=2,c=3") == {"a": "1", "b": "2", "c": "3"}
    assert key_value_pairs_to_dict("a=1;b=2;c=3", delimiter=";", separator="=") == {
        "a": "1",
        "b": "2",
        "c": "3",
    }
    assert key_value_pairs_to_dict("a=1;b=2;c=3", delimiter=";", separator=":") == {
        "a=1": "",
        "b=2": "",
        "c=3": "",
    }
