from .core import RestApiIntegration


class RestApiAwsIntegration(RestApiIntegration):
    """
    This is a REST API integration responsible to directly interact with AWS services. It uses the `uri` to
    map the incoming request to the concerned AWS service, and can have 2 types.
    - `path`: the request is targeting the direct URI of the AWS service, like you would with an HTTP client
     example: For S3 GetObject call: arn:aws:apigateway:us-west-2:s3:path/{bucket}/{key}
    - `action`: this is a simpler way, where you can pass the request parameters like you would do with an SDK, and you
     can specify the service action (for ex. here S3 `GetObject`). It seems the request parameters can be pass as query
     string parameters, JSON body and maybe more. TODO: verify, 2 documentation pages indicates divergent information.
    (one indicates parameters through QS, one through request body)
     example: arn:aws:apigateway:us-west-2:s3:action/GetObject&Bucket={bucket}&Key={key}

    https://docs.aws.amazon.com/apigateway/latest/developerguide/integration-request-basic-setup.html


    TODO: it seems we can global AWS integration type, we should not need to subclass for each service
     we just need to separate usage between the `path` URI type and the `action` URI type.
     - `path`, we can simply pass along the full rendered request along with specific `mocked` AWS headers
     that are dependant of the service (retrieving for the ARN in the uri)
     - `action`, we might need either a full Boto call or use the Boto request serializer, as it seems the request
     parameters are expected as parameters
    """

    name = "AWS"


class RestApiAwsProxyIntegration(RestApiIntegration):
    """
    This is a custom, simplified REST API integration focused only on the Lambda service, with minimal modification from
    API Gateway. It passes the incoming request almost as is, in a custom created event payload, to the configured
    Lambda function.

    https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
    """

    name = "AWS_PROXY"
