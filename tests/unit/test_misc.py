from localstack.utils.aws import aws_stack


def test_environment():
    env = aws_stack.Environment.from_json({'prefix': 'foobar1'})
    assert env.prefix == 'foobar1'
    env = aws_stack.Environment.from_string('foobar2')
    assert env.prefix == 'foobar2'
