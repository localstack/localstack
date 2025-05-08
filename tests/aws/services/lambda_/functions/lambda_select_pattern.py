def handler(event, context):
    status_code = event["statusCode"]
    match status_code:
        case "200":
            return "Pass"
        case "400":
            raise Exception("Error: Raising four hundred from within the Lambda function")
        case "500":
            raise Exception("Error: Raising five hundred from within the Lambda function")
        case _:
            return "Error Value in the json request should either be 400 or 500 to demonstrate"
