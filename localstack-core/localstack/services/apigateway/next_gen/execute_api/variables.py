from typing import Optional, TypedDict


class ContextVarsAuthorizer(TypedDict, total=False):
    # this is merged with the Context returned by the Authorizer, which can attach any property to this dict in string
    # format
    claims: Optional[dict[str, str]]
    principalId: Optional[str]


class ContextVarsIdentityClientCertValidity(TypedDict, total=False):
    notBefore: str
    notAfter: str


class ContextVarsIdentityClientCert(TypedDict, total=False):
    clientCertPem: str
    subjectDN: str
    issuerDN: str
    serialNumber: str
    validity: ContextVarsIdentityClientCertValidity


class ContextVarsIdentity(TypedDict, total=False):
    accountId: str
    apiKey: Optional[str]
    apiKeyId: str
    cognitoAuthenticationProvider: str
    cognitoAuthenticationType: str
    cognitoIdentityId: str
    cognitoIdentityPoolId: str
    principalOrgId: str
    sourceIp: str
    clientCert: ContextVarsIdentityClientCert
    vpcId: str
    vpceId: str
    user: str
    userAgent: str
    userArn: str


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
    apiId: str
    awsEndpointRequestId: str
    deploymentId: str
    domainName: Optional[str]
    domainPrefix: str
    extendedRequestId: str
    httpMethod: str  # TODO: type?
    identity: ContextVarsIdentity
    isCanaryRequest: bool | str  # TODO: verify type
    path: str
    protocol: str
    requestId: str
    requestTime: str
    requestTimeEpoch: str  # TODO: type?
    resourceId: str
    resourcePath: str
    stage: str
    wafResponseCode: Optional[str]
    webaclArn: Optional[str]


class GatewayResponseContextVarsError(TypedDict, total=False):
    # This variable can only be used for simple variable substitution in a GatewayResponse body-mapping template,
    # which is not processed by the Velocity Template Language engine, and in access logging.
    message: str
    messageString: str
    responseType: str
    validationErrorString: str


class LoggingContextVarsAuthorize(TypedDict, total=False):
    error: str
    latency: str
    status: str


class LoggingContextVarsAuthorizer(TypedDict, total=False):
    error: str
    integrationLatency: str
    integrationStatus: str
    latency: str
    requestId: str
    status: str


class LoggingContextVarsAuthenticate(TypedDict, total=False):
    error: str
    latency: str
    status: str


class LoggingContextVarsCustomDomain(TypedDict, total=False):
    basePathMatched: str


class LoggingContextVarsIntegration(TypedDict, total=False):
    error: str
    integrationStatus: str
    latency: str
    requestId: str
    status: str


class LoggingContextVarsWaf(TypedDict, total=False):
    error: str
    latency: str
    status: str


class LoggingContextVariables(TypedDict, total=False):
    authorize: LoggingContextVarsAuthorize
    authorizer: LoggingContextVarsAuthorizer
    authenticate: LoggingContextVarsAuthenticate
    customDomain: LoggingContextVarsCustomDomain
    endpointType: str
    integration: LoggingContextVarsIntegration
    integrationLatency: str
    integrationStatus: str
    responseLatency: str
    responseLength: str
    status: str
    waf: LoggingContextVarsWaf
    xrayTraceId: str
