import json


def lambda_handler(event, context):
    # Just print the event was passed to lambda
    print('{}'.format(json.dumps(event)))
    return 0
