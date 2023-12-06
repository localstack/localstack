def handler(event, context):
    status_code = event["statusCode"]
    match status_code:
        case "200":
            return "Pass"
        case "400":
            raise Exception("Error: Raising 400 from within the Lambda function")
        case "500":
            raise Exception("Error: Raising 500 from within the Lambda function")
        case _:
            return "Error Value in the json request should either be 400 or 500 to demonstrate"
