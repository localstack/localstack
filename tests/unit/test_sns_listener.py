import json
from nose.tools import assert_equal
from localstack.services.sns import sns_listener


def test_create_sns_message_body_raw_message_delivery():
    subscriber = {
        'RawMessageDelivery': 'true'
    }
    action = {
        'Message': ['msg']
    }
    result = sns_listener.create_sns_message_body(subscriber, action)
    assert (result == 'msg')


def test_create_sns_message_body():
    subscriber = {
        'TopicArn': 'arn',
        'RawMessageDelivery': 'false',
    }
    action = {
        'Message': ['msg']
    }
    result = sns_listener.create_sns_message_body(subscriber, action)
    assert_equal(json.loads(result), {'Message': 'msg', 'Type': 'Notification', 'TopicArn': 'arn'})

    # Now add a subject
    action = {
        'Message': ['msg'],
        'Subject': ['subject'],
        'MessageAttributes.entry.0.Name': ['attr1'],
        'MessageAttributes.entry.0.Value.DataType': ['String'],
        'MessageAttributes.entry.0.Value.StringValue': ['value1'],
        'MessageAttributes.entry.0.Value.BinaryValue': ['value1'],
        'MessageAttributes.entry.1.Name': ['attr2'],
        'MessageAttributes.entry.1.Value.DataType': ['String'],
        'MessageAttributes.entry.1.Value.StringValue': ['value2'],
        'MessageAttributes.entry.1.Value.BinaryValue': ['value2'],
    }
    result = sns_listener.create_sns_message_body(subscriber, action)
    expected = json.dumps({'Message': 'msg',
                           'TopicArn': 'arn',
                           'Type': 'Notification',
                           'Subject': 'subject',
                           'MessageAttributes': {
                               'attr1': {
                                   'Type': 'String',
                                   'Value': 'value1',
                               }, 'attr2': {
                                   'Type': 'String',
                                   'Value': 'value2',
                               }
                           }})
    assert_equal(json.loads(result), json.loads(expected))
