import os


def handler(event, context):
    init_type = os.environ["AWS_LAMBDA_INITIALIZATION_TYPE"]
    print(f"{init_type=}")
    return init_type
