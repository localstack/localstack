from .core import RestApiIntegration


class RestApiMockIntegration(RestApiIntegration):
    """
    This is a simple REST API integration but quite limited, allowing you to quickly test your APIs or return
    hardcoded responses to the client.
    This integration can never return a proper response, and all the work is done with integration request and response
    mappings.
    This can be used to set up CORS response for `OPTIONS` requests.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-mock-integration.html
    """

    name = "MOCK"
