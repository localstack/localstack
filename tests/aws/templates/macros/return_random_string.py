import random
import string


def handler(event, context):
    parameters = event["templateParameterValues"]
    fragment = f"{parameters['Input']}-{random_string(5)}"
    resp = {"requestId": event["requestId"], "status": "success", "fragment": fragment}

    return resp


def random_string(length):
    return "".join(random.choice(string.ascii_lowercase) for i in range(length))
