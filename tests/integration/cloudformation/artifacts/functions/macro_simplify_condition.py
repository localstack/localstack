import json
import logging
logging.basicConfig(level=logging.INFO)

def handler(event, context):
    logging.info("Hello!")

    fragment = {
        "Resources": {
            "MyNewTopic": {
                "Type": "AWS::SNS::Topic"
            }
        }
    }

    return {
        "requestId": event["requestId"],
        "status": "success",
        "fragment": event["fragment"],
    }