def handler(event, ctx):
    print("generating bytes...")
    bytenum = event["bytenum"]
    return "a" * bytenum
