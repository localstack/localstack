import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def handler(event, ctx):
    verification_token = event["verification_token"]
    logging.info(f"{verification_token=}")
    return {"verification_token": verification_token}
