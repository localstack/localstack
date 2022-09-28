def handler(event, ctx):
    verification_token = event["verification_token"]
    print(f"{verification_token=}")
    return {"verification_token": verification_token}
