import os
import time

def handler(event, context):
    """ Simple Lambda function that returns values related to the context initially time remaining """
    try:
        body = json.loads(event['body'])
    except Exception:
        body = event

    seconds_to_sleep = (int(body["seconds_to_sleep"]) or 0)

    time.sleep(seconds_to_sleep)

    return { 'TimeRemainingInMillis': context.get_remaining_time_in_millis(),
             'SecondsISlept': seconds_to_sleep }
