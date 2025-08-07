from typing import TypedDict


class ContextVarsAuthorizer(TypedDict, total=False):
    # this is merged with the Context returned by the Authorizer, which can attach any property to this dict in string
    # format

    # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
    claims: dict[str, str] | None
    """Claims returned from the Amazon Cognito user pool after the method caller is successfully authenticated"""
    principalId: str | None
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
    accountId: str | None
    """The AWS account ID associated with the request."""
    accessKey: str | None
    """The AWS access key associated with the request."""
    apiKey: str | None
    """For API methods that require an API key, this variable is the API key associated with the method request."""
    apiKeyId: str | None
    """The API key ID associated with an API request that requires an API key."""
    caller: str | None
    """The principal identifier of the caller that signed the request. Supported for resources that use IAM authorization."""
    cognitoAuthenticationProvider: str | None
    """A comma-separated list of the Amazon Cognito authentication providers used by the caller making the request"""
    cognitoAuthenticationType: str | None
    """The Amazon Cognito authentication type of the caller making the request"""
    cognitoIdentityId: str | None
    """The Amazon Cognito identity ID of the caller making the request"""
    cognitoIdentityPoolId: str | None
    """The Amazon Cognito identity pool ID of the caller making the request"""
    principalOrgId: str | None
    """The AWS organization ID."""
    sourceIp: str | None
    """The source IP address of the immediate TCP connection making the request to the API Gateway endpoint"""
    clientCert: ContextVarsIdentityClientCert
    vpcId: str | None
    """The VPC ID of the VPC making the request to the API Gateway endpoint."""
    vpceId: str | None
    """The VPC endpoint ID of the VPC endpoint making the request to the API Gateway endpoint."""
    user: str | None
    """The principal identifier of the user that will be authorized against resource access for resources that use IAM authorization."""
    userAgent: str | None
    """The User-Agent header of the API caller."""
    userArn: str | None
    """The Amazon Resource Name (ARN) of the effective user identified after authentication."""


class ContextVarsRequestOverride(TypedDict, total=False):
    header: dict[str, str]
    path: dict[str, str]
    querystring: dict[str, str]


class ContextVarsResponseOverride(TypedDict):
    header: dict[str, str]
    status: int


class ContextVariableOverrides(TypedDict):
    requestOverride: ContextVarsRequestOverride
    responseOverride: ContextVarsResponseOverride


class GatewayResponseContextVarsError(TypedDict, total=False):
    # This variable can only be used for simple variable substitution in a GatewayResponse body-mapping template,
    # which is not processed by the Velocity Template Language engine, and in access logging.
    message: str
    messageString: str
    responseType: str
    validationErrorString: str


class ContextVariables(TypedDict, total=False):
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html#context-variable-reference
    accountId: str
    """The API owner's AWS account ID."""
    apiId: str
    """The identifier API Gateway assigns to your API."""
    authorizer: ContextVarsAuthorizer | None
    """The principal user identification associated with the token."""
    awsEndpointRequestId: str | None
    """The AWS endpoint's request ID."""
    deploymentId: str
    """The ID of the API deployment."""
    domainName: str
    """The full domain name used to invoke the API. This should be the same as the incoming Host header."""
    domainPrefix: str
    """The first label of the $context.domainName."""
    error: GatewayResponseContextVarsError
    """The error context variables."""
    extendedRequestId: str
    """The extended ID that API Gateway generates and assigns to the API request. """
    httpMethod: str
    """The HTTP method used"""
    identity: ContextVarsIdentity | None
    isCanaryRequest: bool | None
    """Indicates if the request was directed to the canary"""
    path: str
    """The request path."""
    protocol: str
    """The request protocol"""
    requestId: str
    """An ID for the request. Clients can override this request ID. """
    requestOverride: ContextVarsRequestOverride | None
    """Request override. Only exists for request mapping template"""
    requestTime: str
    """The CLF-formatted request time (dd/MMM/yyyy:HH:mm:ss +-hhmm)."""
    requestTimeEpoch: int
    """The Epoch-formatted request time, in milliseconds."""
    resourceId: str | None
    """The identifier that API Gateway assigns to your resource."""
    resourcePath: str | None
    """The path to your resource"""
    responseOverride: ContextVarsResponseOverride | None
    """Response override. Only exists for response mapping template"""
    stage: str
    """The deployment stage of the API request """
    wafResponseCode: str | None
    """The response received from AWS WAF: WAF_ALLOW or WAF_BLOCK. Will not be set if the stage is not associated with a web ACL"""
    webaclArn: str | None
    """The complete ARN of the web ACL that is used to decide whether to allow or block the request. Will not be set if the stage is not associated with a web ACL."""


class LoggingContextVarsAuthorize(TypedDict, total=False):
    error: str | None
    latency: str | None
    status: str | None


class LoggingContextVarsAuthorizer(TypedDict, total=False):
    error: str | None
    integrationLatency: str | None
    integrationStatus: str | None
    latency: str | None
    requestId: str | None
    status: str | None


class LoggingContextVarsAuthenticate(TypedDict, total=False):
    error: str | None
    latency: str | None
    status: str | None


class LoggingContextVarsCustomDomain(TypedDict, total=False):
    basePathMatched: str | None


class LoggingContextVarsIntegration(TypedDict, total=False):
    error: str | None
    integrationStatus: str | None
    latency: str | None
    requestId: str | None
    status: str | None


class LoggingContextVarsWaf(TypedDict, total=False):
    error: str | None
    latency: str | None
    status: str | None


class LoggingContextVariables(TypedDict, total=False):
    authorize: LoggingContextVarsAuthorize | None
    authorizer: LoggingContextVarsAuthorizer | None
    authenticate: LoggingContextVarsAuthenticate | None
    customDomain: LoggingContextVarsCustomDomain | None
    endpointType: str | None
    integration: LoggingContextVarsIntegration | None
    integrationLatency: str | None
    integrationStatus: str | None
    responseLatency: str | None
    responseLength: str | None
    status: str | None
    waf: LoggingContextVarsWaf | None
    xrayTraceId: str | None
