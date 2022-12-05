def handler(event, context):
    fragment = add_standard_attributes(event["fragment"])

    return {"requestId": event["requestId"], "status": "success", "fragment": fragment}


def add_standard_attributes(fragment):
    # add .fifo
    if ".fifo" not in fragment["TopicName"]:
        fragment["TopicName"] = f"{fragment['TopicName']}.fifo"

    fragment["FifoTopic"] = True
    fragment["ContentBaseDeduplication"] = True

    return fragment
