import json
from nose.tools import assert_equal
from localstack.services.sns import sns_listener


def test_unsubscribe_without_arn_should_error():
    sns = sns_listener.ProxyListenerSNS()
    error = sns.forward_request('POST', '/', 'Action=Unsubscribe', '')
    assert(error is not None)
    assert(error.status_code == 400)


def test_unsubscribe_should_remove_listener():
    sub_arn = 'arn:aws:sns:us-east-1:123456789012:test-topic:45e61c7f-dca5-4fcd-be2b-4e1b0d6eef72'
    topic_arn = 'arn:aws:sns:us-east-1:123456789012:test-topic'

    assert(sns_listener.get_topic_by_arn(topic_arn) is None)
    sns_listener.do_create_topic(topic_arn)
    assert(sns_listener.get_topic_by_arn(topic_arn) is not None)
    sns_listener.do_subscribe(topic_arn,
                     'http://localhost:1234/listen',
                     'http',
                     sub_arn)
    assert(sns_listener.get_subscription_by_arn(sub_arn) is not None)
    sns_listener.do_unsubscribe(sub_arn)
    assert(sns_listener.get_subscription_by_arn(sub_arn) is None)


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
        'MessageAttributes.entry.1.Name': ['attr1'],
        'MessageAttributes.entry.1.Value.DataType': ['String'],
        'MessageAttributes.entry.1.Value.StringValue': ['value1'],
        'MessageAttributes.entry.1.Value.BinaryValue': ['value1'],
        'MessageAttributes.entry.2.Name': ['attr2'],
        'MessageAttributes.entry.2.Value.DataType': ['String'],
        'MessageAttributes.entry.2.Value.StringValue': ['value2'],
        'MessageAttributes.entry.2.Value.BinaryValue': ['value2'],
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
