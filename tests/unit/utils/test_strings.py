from localstack.utils.strings import prepend_with_slash


def test_prepend_with_slash():
    assert prepend_with_slash("hello") == "/hello"
    assert prepend_with_slash("/world") == "/world"
    assert prepend_with_slash("//world") == "//world"
