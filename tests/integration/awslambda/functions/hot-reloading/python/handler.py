CONSTANT_VARIABLE = "value1"
COUNTER = 0


def handler(event, context):
    global COUNTER
    COUNTER += 1
    return {"counter": COUNTER, "constant": CONSTANT_VARIABLE}
