counter = 0


def handler(event, context):
    global counter
    result = {"counter": counter}
    counter += 1
    return result
