from typing import Optional, TypedDict


class ContextVarsAuthorizer(TypedDict, total=False):
    # this is merged with the Context returned by the Authorizer, which can attach any property to this dict in string
    # format

    # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
    claims: Optional[dict[str, str]]
    """Claims returned from the Amazon Cognito user pool after the method caller is successfully authenticated"""
    principal_id: Optional[str]
    """The principal user identification associated with the token sent by the client and returned from an API Gateway Lambda authorizer"""


class ContextVarsIdentityClientCertValidity(TypedDict, total=False):
    notBefore: str
    notAfter: str


class ContextVarsIdentityClientCert(TypedDict, total=False):
    """Certificate that a client presents. Present only in access logs if mutual TLS authentication fails."""

    clientCertPem: str
    subjectDN: str
    issuerDN: str
    serialNumber: str
    validity: ContextVarsIdentityClientCertValidity


class ContextVarsIdentity(TypedDict, total=False):
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
    accountId: Optional[str]
    """The AWS account ID associated with the request."""
    apiKey: Optional[str]
    """For API methods that require an API key, this variable is the API key associated with the method request."""
    apiKeyId: Optional[str]
    """The API key ID associated with an API request that requires an API key."""
    caller: Optional[str]
    """The principal identifier of the caller that signed the request. Supported for resources that use IAM authorization."""
    cognitoAuthenticationProvider: Optional[str]
    """A comma-separated list of the Amazon Cognito authentication providers used by the caller making the request"""
    cognitoAuthenticationType: Optional[str]
    """The Amazon Cognito authentication type of the caller making the request"""
    cognitoIdentityId: Optional[str]
    """The Amazon Cognito identity ID of the caller making the request"""
    cognitoIdentityPoolId: Optional[str]
    """The Amazon Cognito identity pool ID of the caller making the request"""
    principalOrgId: Optional[str]
    """The AWS organization ID."""
    sourceIp: Optional[str]
    """The source IP address of the immediate TCP connection making the request to the API Gateway endpoint"""
    clientCert: ContextVarsIdentityClientCert
    vpcId: Optional[str]
    """The VPC ID of the VPC making the request to the API Gateway endpoint."""
    vpceId: Optional[str]
    """The VPC endpoint ID of the VPC endpoint making the request to the API Gateway endpoint."""
    user: Optional[str]
    """The principal identifier of the user that will be authorized against resource access for resources that use IAM authorization."""
    userAgent: Optional[str]
    """The User-Agent header of the API caller."""
    userArn: Optional[str]
    """The Amazon Resource Name (ARN) of the effective user identified after authentication."""


class ContextVarsRequestOverride(TypedDict, total=False):
    header: dict[str, str]
    path: dict[str, str]
    querystring: dict[str, str]


class ContextVarsResponseOverride(TypedDict, total=False):
    header: dict[str, str]
    querystring: dict[str, str]
    status: int


class ContextVariables(TypedDict, total=False):
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html#context-variable-reference
    accountId: str
    """The API owner's AWS account ID."""
    apiId: str
    """The identifier API Gateway assigns to your API."""
    awsEndpointRequestId: Optional[str]
    """The AWS endpoint's request ID."""
    deploymentId: str
    """The ID of the API deployment."""
    domainName: str
    """The full domain name used to invoke the API. This should be the same as the incoming Host header."""
    domainPrefix: str
    """The first label of the $context.domainName."""
    extendedRequestId: str
    """The extended ID that API Gateway generates and assigns to the API request. """
    httpMethod: str
    """The HTTP method used"""
    identity: Optional[ContextVarsIdentity]
    isCanaryRequest: Optional[bool | str]  # TODO: verify type
    """Indicates if the request was directed to the canary"""
    path: str
    """The request path."""
    protocol: str
    """The request protocol"""
    requestId: str
    """An ID for the request. Clients can override this request ID. """
    requestTime: str
    """The CLF-formatted request time (dd/MMM/yyyy:HH:mm:ss +-hhmm)."""
    requestTimeEpoch: int
    """The Epoch-formatted request time, in milliseconds."""
    resourceId: Optional[str]
    """The identifier that API Gateway assigns to your resource."""
    resourcePath: Optional[str]
    """The path to your resource"""
    stage: str
    """The deployment stage of the API request """
    wafResponseCode: Optional[str]
    """The response received from AWS WAF: WAF_ALLOW or WAF_BLOCK. Will not be set if the stage is not associated with a web ACL"""
    webaclArn: Optional[str]
    """The complete ARN of the web ACL that is used to decide whether to allow or block the request. Will not be set if the stage is not associated with a web ACL."""


class GatewayResponseContextVarsError(TypedDict, total=False):
    # This variable can only be used for simple variable substitution in a GatewayResponse body-mapping template,
    # which is not processed by the Velocity Template Language engine, and in access logging.
    message: str
    messageString: str
    responseType: str
    validationErrorString: str


class LoggingContextVarsAuthorize(TypedDict, total=False):
    error: Optional[str]
    latency: Optional[str]
    status: Optional[str]


class LoggingContextVarsAuthorizer(TypedDict, total=False):
    error: Optional[str]
    integrationLatency: Optional[str]
    integrationStatus: Optional[str]
    latency: Optional[str]
    requestId: Optional[str]
    status: Optional[str]


class LoggingContextVarsAuthenticate(TypedDict, total=False):
    error: Optional[str]
    latency: Optional[str]
    status: Optional[str]


class LoggingContextVarsCustomDomain(TypedDict, total=False):
    basePathMatched: Optional[str]


class LoggingContextVarsIntegration(TypedDict, total=False):
    error: Optional[str]
    integrationStatus: Optional[str]
    latency: Optional[str]
    requestId: Optional[str]
    status: Optional[str]


class LoggingContextVarsWaf(TypedDict, total=False):
    error: Optional[str]
    latency: Optional[str]
    status: Optional[str]


class LoggingContextVariables(TypedDict, total=False):
    authorize: Optional[LoggingContextVarsAuthorize]
    authorizer: Optional[LoggingContextVarsAuthorizer]
    authenticate: Optional[LoggingContextVarsAuthenticate]
    customDomain: Optional[LoggingContextVarsCustomDomain]
    endpointType: Optional[str]
    integration: Optional[LoggingContextVarsIntegration]
    integrationLatency: Optional[str]
    integrationStatus: Optional[str]
    responseLatency: Optional[str]
    responseLength: Optional[str]
    status: Optional[str]
    waf: Optional[LoggingContextVarsWaf]
    xrayTraceId: Optional[str]
