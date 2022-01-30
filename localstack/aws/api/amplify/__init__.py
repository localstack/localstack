import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccessToken = str
ActiveJobId = str
AppArn = str
AppId = str
ArtifactFileName = str
ArtifactId = str
ArtifactUrl = str
ArtifactsUrl = str
AssociatedResource = str
AutoBranchCreationPattern = str
AutoSubDomainCreationPattern = str
AutoSubDomainIAMRole = str
BackendEnvironmentArn = str
BasicAuthCredentials = str
BranchArn = str
BranchName = str
BuildSpec = str
CertificateVerificationDNSRecord = str
Code = str
CommitId = str
CommitMessage = str
Condition = str
Context = str
CustomDomain = str
CustomHeaders = str
DNSRecord = str
DefaultDomain = str
DeploymentArtifacts = str
Description = str
DisplayName = str
DomainAssociationArn = str
DomainName = str
DomainPrefix = str
EnableAutoBranchCreation = bool
EnableAutoBuild = bool
EnableAutoSubDomain = bool
EnableBasicAuth = bool
EnableBranchAutoBuild = bool
EnableBranchAutoDeletion = bool
EnableNotification = bool
EnablePerformanceMode = bool
EnablePullRequestPreview = bool
EnvKey = str
EnvValue = str
EnvironmentName = str
ErrorMessage = str
FileName = str
Framework = str
JobArn = str
JobId = str
JobReason = str
LogUrl = str
MD5Hash = str
MaxResults = int
Name = str
NextToken = str
OauthToken = str
PullRequestEnvironmentName = str
Repository = str
ResourceArn = str
ServiceRoleArn = str
Source = str
SourceUrl = str
StackName = str
Status = str
StatusReason = str
StepName = str
TTL = str
TagKey = str
TagValue = str
Target = str
TestArtifactsUrl = str
TestConfigUrl = str
ThumbnailName = str
ThumbnailUrl = str
TotalNumberOfJobs = str
UploadUrl = str
Verified = bool
WebhookArn = str
WebhookId = str
WebhookUrl = str


class DomainStatus(str):
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    IN_PROGRESS = "IN_PROGRESS"
    AVAILABLE = "AVAILABLE"
    PENDING_DEPLOYMENT = "PENDING_DEPLOYMENT"
    FAILED = "FAILED"
    CREATING = "CREATING"
    REQUESTING_CERTIFICATE = "REQUESTING_CERTIFICATE"
    UPDATING = "UPDATING"


class JobStatus(str):
    PENDING = "PENDING"
    PROVISIONING = "PROVISIONING"
    RUNNING = "RUNNING"
    FAILED = "FAILED"
    SUCCEED = "SUCCEED"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"


class JobType(str):
    RELEASE = "RELEASE"
    RETRY = "RETRY"
    MANUAL = "MANUAL"
    WEB_HOOK = "WEB_HOOK"


class Platform(str):
    WEB = "WEB"
    WEB_DYNAMIC = "WEB_DYNAMIC"


class RepositoryCloneMethod(str):
    SSH = "SSH"
    TOKEN = "TOKEN"
    SIGV4 = "SIGV4"


class Stage(str):
    PRODUCTION = "PRODUCTION"
    BETA = "BETA"
    DEVELOPMENT = "DEVELOPMENT"
    EXPERIMENTAL = "EXPERIMENTAL"
    PULL_REQUEST = "PULL_REQUEST"


class BadRequestException(ServiceException):
    message: Optional[ErrorMessage]


class DependentServiceFailureException(ServiceException):
    message: Optional[ErrorMessage]


class InternalFailureException(ServiceException):
    message: Optional[ErrorMessage]


class LimitExceededException(ServiceException):
    message: Optional[ErrorMessage]


class NotFoundException(ServiceException):
    message: Optional[ErrorMessage]


class ResourceNotFoundException(ServiceException):
    code: Code
    message: ErrorMessage


class UnauthorizedException(ServiceException):
    message: Optional[ErrorMessage]


EnvironmentVariables = Dict[EnvKey, EnvValue]


class AutoBranchCreationConfig(TypedDict, total=False):
    stage: Optional[Stage]
    framework: Optional[Framework]
    enableAutoBuild: Optional[EnableAutoBuild]
    environmentVariables: Optional[EnvironmentVariables]
    basicAuthCredentials: Optional[BasicAuthCredentials]
    enableBasicAuth: Optional[EnableBasicAuth]
    enablePerformanceMode: Optional[EnablePerformanceMode]
    buildSpec: Optional[BuildSpec]
    enablePullRequestPreview: Optional[EnablePullRequestPreview]
    pullRequestEnvironmentName: Optional[PullRequestEnvironmentName]


AutoBranchCreationPatterns = List[AutoBranchCreationPattern]
LastDeployTime = datetime


class ProductionBranch(TypedDict, total=False):
    lastDeployTime: Optional[LastDeployTime]
    status: Optional[Status]
    thumbnailUrl: Optional[ThumbnailUrl]
    branchName: Optional[BranchName]


class CustomRule(TypedDict, total=False):
    source: Source
    target: Target
    status: Optional[Status]
    condition: Optional[Condition]


CustomRules = List[CustomRule]
UpdateTime = datetime
CreateTime = datetime
TagMap = Dict[TagKey, TagValue]


class App(TypedDict, total=False):
    appId: AppId
    appArn: AppArn
    name: Name
    tags: Optional[TagMap]
    description: Description
    repository: Repository
    platform: Platform
    createTime: CreateTime
    updateTime: UpdateTime
    iamServiceRoleArn: Optional[ServiceRoleArn]
    environmentVariables: EnvironmentVariables
    defaultDomain: DefaultDomain
    enableBranchAutoBuild: EnableBranchAutoBuild
    enableBranchAutoDeletion: Optional[EnableBranchAutoDeletion]
    enableBasicAuth: EnableBasicAuth
    basicAuthCredentials: Optional[BasicAuthCredentials]
    customRules: Optional[CustomRules]
    productionBranch: Optional[ProductionBranch]
    buildSpec: Optional[BuildSpec]
    customHeaders: Optional[CustomHeaders]
    enableAutoBranchCreation: Optional[EnableAutoBranchCreation]
    autoBranchCreationPatterns: Optional[AutoBranchCreationPatterns]
    autoBranchCreationConfig: Optional[AutoBranchCreationConfig]
    repositoryCloneMethod: Optional[RepositoryCloneMethod]


Apps = List[App]


class Artifact(TypedDict, total=False):
    artifactFileName: ArtifactFileName
    artifactId: ArtifactId


Artifacts = List[Artifact]
AssociatedResources = List[AssociatedResource]
AutoSubDomainCreationPatterns = List[AutoSubDomainCreationPattern]


class BackendEnvironment(TypedDict, total=False):
    backendEnvironmentArn: BackendEnvironmentArn
    environmentName: EnvironmentName
    stackName: Optional[StackName]
    deploymentArtifacts: Optional[DeploymentArtifacts]
    createTime: CreateTime
    updateTime: UpdateTime


BackendEnvironments = List[BackendEnvironment]
CustomDomains = List[CustomDomain]


class Branch(TypedDict, total=False):
    branchArn: BranchArn
    branchName: BranchName
    description: Description
    tags: Optional[TagMap]
    stage: Stage
    displayName: DisplayName
    enableNotification: EnableNotification
    createTime: CreateTime
    updateTime: UpdateTime
    environmentVariables: EnvironmentVariables
    enableAutoBuild: EnableAutoBuild
    customDomains: CustomDomains
    framework: Framework
    activeJobId: ActiveJobId
    totalNumberOfJobs: TotalNumberOfJobs
    enableBasicAuth: EnableBasicAuth
    enablePerformanceMode: Optional[EnablePerformanceMode]
    thumbnailUrl: Optional[ThumbnailUrl]
    basicAuthCredentials: Optional[BasicAuthCredentials]
    buildSpec: Optional[BuildSpec]
    ttl: TTL
    associatedResources: Optional[AssociatedResources]
    enablePullRequestPreview: EnablePullRequestPreview
    pullRequestEnvironmentName: Optional[PullRequestEnvironmentName]
    destinationBranch: Optional[BranchName]
    sourceBranch: Optional[BranchName]
    backendEnvironmentArn: Optional[BackendEnvironmentArn]


Branches = List[Branch]
CommitTime = datetime


class CreateAppRequest(ServiceRequest):
    name: Name
    description: Optional[Description]
    repository: Optional[Repository]
    platform: Optional[Platform]
    iamServiceRoleArn: Optional[ServiceRoleArn]
    oauthToken: Optional[OauthToken]
    accessToken: Optional[AccessToken]
    environmentVariables: Optional[EnvironmentVariables]
    enableBranchAutoBuild: Optional[EnableBranchAutoBuild]
    enableBranchAutoDeletion: Optional[EnableBranchAutoDeletion]
    enableBasicAuth: Optional[EnableBasicAuth]
    basicAuthCredentials: Optional[BasicAuthCredentials]
    customRules: Optional[CustomRules]
    tags: Optional[TagMap]
    buildSpec: Optional[BuildSpec]
    customHeaders: Optional[CustomHeaders]
    enableAutoBranchCreation: Optional[EnableAutoBranchCreation]
    autoBranchCreationPatterns: Optional[AutoBranchCreationPatterns]
    autoBranchCreationConfig: Optional[AutoBranchCreationConfig]


class CreateAppResult(TypedDict, total=False):
    app: App


class CreateBackendEnvironmentRequest(ServiceRequest):
    appId: AppId
    environmentName: EnvironmentName
    stackName: Optional[StackName]
    deploymentArtifacts: Optional[DeploymentArtifacts]


class CreateBackendEnvironmentResult(TypedDict, total=False):
    backendEnvironment: BackendEnvironment


class CreateBranchRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    description: Optional[Description]
    stage: Optional[Stage]
    framework: Optional[Framework]
    enableNotification: Optional[EnableNotification]
    enableAutoBuild: Optional[EnableAutoBuild]
    environmentVariables: Optional[EnvironmentVariables]
    basicAuthCredentials: Optional[BasicAuthCredentials]
    enableBasicAuth: Optional[EnableBasicAuth]
    enablePerformanceMode: Optional[EnablePerformanceMode]
    tags: Optional[TagMap]
    buildSpec: Optional[BuildSpec]
    ttl: Optional[TTL]
    displayName: Optional[DisplayName]
    enablePullRequestPreview: Optional[EnablePullRequestPreview]
    pullRequestEnvironmentName: Optional[PullRequestEnvironmentName]
    backendEnvironmentArn: Optional[BackendEnvironmentArn]


class CreateBranchResult(TypedDict, total=False):
    branch: Branch


FileMap = Dict[FileName, MD5Hash]


class CreateDeploymentRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    fileMap: Optional[FileMap]


FileUploadUrls = Dict[FileName, UploadUrl]


class CreateDeploymentResult(TypedDict, total=False):
    jobId: Optional[JobId]
    fileUploadUrls: FileUploadUrls
    zipUploadUrl: UploadUrl


class SubDomainSetting(TypedDict, total=False):
    prefix: DomainPrefix
    branchName: BranchName


SubDomainSettings = List[SubDomainSetting]


class CreateDomainAssociationRequest(ServiceRequest):
    appId: AppId
    domainName: DomainName
    enableAutoSubDomain: Optional[EnableAutoSubDomain]
    subDomainSettings: SubDomainSettings
    autoSubDomainCreationPatterns: Optional[AutoSubDomainCreationPatterns]
    autoSubDomainIAMRole: Optional[AutoSubDomainIAMRole]


class SubDomain(TypedDict, total=False):
    subDomainSetting: SubDomainSetting
    verified: Verified
    dnsRecord: DNSRecord


SubDomains = List[SubDomain]


class DomainAssociation(TypedDict, total=False):
    domainAssociationArn: DomainAssociationArn
    domainName: DomainName
    enableAutoSubDomain: EnableAutoSubDomain
    autoSubDomainCreationPatterns: Optional[AutoSubDomainCreationPatterns]
    autoSubDomainIAMRole: Optional[AutoSubDomainIAMRole]
    domainStatus: DomainStatus
    statusReason: StatusReason
    certificateVerificationDNSRecord: Optional[CertificateVerificationDNSRecord]
    subDomains: SubDomains


class CreateDomainAssociationResult(TypedDict, total=False):
    domainAssociation: DomainAssociation


class CreateWebhookRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    description: Optional[Description]


class Webhook(TypedDict, total=False):
    webhookArn: WebhookArn
    webhookId: WebhookId
    webhookUrl: WebhookUrl
    branchName: BranchName
    description: Description
    createTime: CreateTime
    updateTime: UpdateTime


class CreateWebhookResult(TypedDict, total=False):
    webhook: Webhook


class DeleteAppRequest(ServiceRequest):
    appId: AppId


class DeleteAppResult(TypedDict, total=False):
    app: App


class DeleteBackendEnvironmentRequest(ServiceRequest):
    appId: AppId
    environmentName: EnvironmentName


class DeleteBackendEnvironmentResult(TypedDict, total=False):
    backendEnvironment: BackendEnvironment


class DeleteBranchRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName


class DeleteBranchResult(TypedDict, total=False):
    branch: Branch


class DeleteDomainAssociationRequest(ServiceRequest):
    appId: AppId
    domainName: DomainName


class DeleteDomainAssociationResult(TypedDict, total=False):
    domainAssociation: DomainAssociation


class DeleteJobRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    jobId: JobId


EndTime = datetime
StartTime = datetime


class JobSummary(TypedDict, total=False):
    jobArn: JobArn
    jobId: JobId
    commitId: CommitId
    commitMessage: CommitMessage
    commitTime: CommitTime
    startTime: StartTime
    status: JobStatus
    endTime: Optional[EndTime]
    jobType: JobType


class DeleteJobResult(TypedDict, total=False):
    jobSummary: JobSummary


class DeleteWebhookRequest(ServiceRequest):
    webhookId: WebhookId


class DeleteWebhookResult(TypedDict, total=False):
    webhook: Webhook


DomainAssociations = List[DomainAssociation]


class GenerateAccessLogsRequest(ServiceRequest):
    startTime: Optional[StartTime]
    endTime: Optional[EndTime]
    domainName: DomainName
    appId: AppId


class GenerateAccessLogsResult(TypedDict, total=False):
    logUrl: Optional[LogUrl]


class GetAppRequest(ServiceRequest):
    appId: AppId


class GetAppResult(TypedDict, total=False):
    app: App


class GetArtifactUrlRequest(ServiceRequest):
    artifactId: ArtifactId


class GetArtifactUrlResult(TypedDict, total=False):
    artifactId: ArtifactId
    artifactUrl: ArtifactUrl


class GetBackendEnvironmentRequest(ServiceRequest):
    appId: AppId
    environmentName: EnvironmentName


class GetBackendEnvironmentResult(TypedDict, total=False):
    backendEnvironment: BackendEnvironment


class GetBranchRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName


class GetBranchResult(TypedDict, total=False):
    branch: Branch


class GetDomainAssociationRequest(ServiceRequest):
    appId: AppId
    domainName: DomainName


class GetDomainAssociationResult(TypedDict, total=False):
    domainAssociation: DomainAssociation


class GetJobRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    jobId: JobId


Screenshots = Dict[ThumbnailName, ThumbnailUrl]


class Step(TypedDict, total=False):
    stepName: StepName
    startTime: StartTime
    status: JobStatus
    endTime: EndTime
    logUrl: Optional[LogUrl]
    artifactsUrl: Optional[ArtifactsUrl]
    testArtifactsUrl: Optional[TestArtifactsUrl]
    testConfigUrl: Optional[TestConfigUrl]
    screenshots: Optional[Screenshots]
    statusReason: Optional[StatusReason]
    context: Optional[Context]


Steps = List[Step]


class Job(TypedDict, total=False):
    summary: JobSummary
    steps: Steps


class GetJobResult(TypedDict, total=False):
    job: Job


class GetWebhookRequest(ServiceRequest):
    webhookId: WebhookId


class GetWebhookResult(TypedDict, total=False):
    webhook: Webhook


JobSummaries = List[JobSummary]


class ListAppsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListAppsResult(TypedDict, total=False):
    apps: Apps
    nextToken: Optional[NextToken]


class ListArtifactsRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    jobId: JobId
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListArtifactsResult(TypedDict, total=False):
    artifacts: Artifacts
    nextToken: Optional[NextToken]


class ListBackendEnvironmentsRequest(ServiceRequest):
    appId: AppId
    environmentName: Optional[EnvironmentName]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListBackendEnvironmentsResult(TypedDict, total=False):
    backendEnvironments: BackendEnvironments
    nextToken: Optional[NextToken]


class ListBranchesRequest(ServiceRequest):
    appId: AppId
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListBranchesResult(TypedDict, total=False):
    branches: Branches
    nextToken: Optional[NextToken]


class ListDomainAssociationsRequest(ServiceRequest):
    appId: AppId
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListDomainAssociationsResult(TypedDict, total=False):
    domainAssociations: DomainAssociations
    nextToken: Optional[NextToken]


class ListJobsRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListJobsResult(TypedDict, total=False):
    jobSummaries: JobSummaries
    nextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: ResourceArn


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[TagMap]


class ListWebhooksRequest(ServiceRequest):
    appId: AppId
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


Webhooks = List[Webhook]


class ListWebhooksResult(TypedDict, total=False):
    webhooks: Webhooks
    nextToken: Optional[NextToken]


class StartDeploymentRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    jobId: Optional[JobId]
    sourceUrl: Optional[SourceUrl]


class StartDeploymentResult(TypedDict, total=False):
    jobSummary: JobSummary


class StartJobRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    jobId: Optional[JobId]
    jobType: JobType
    jobReason: Optional[JobReason]
    commitId: Optional[CommitId]
    commitMessage: Optional[CommitMessage]
    commitTime: Optional[CommitTime]


class StartJobResult(TypedDict, total=False):
    jobSummary: JobSummary


class StopJobRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    jobId: JobId


class StopJobResult(TypedDict, total=False):
    jobSummary: JobSummary


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceArn: ResourceArn
    tags: TagMap


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceArn: ResourceArn
    tagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateAppRequest(ServiceRequest):
    appId: AppId
    name: Optional[Name]
    description: Optional[Description]
    platform: Optional[Platform]
    iamServiceRoleArn: Optional[ServiceRoleArn]
    environmentVariables: Optional[EnvironmentVariables]
    enableBranchAutoBuild: Optional[EnableAutoBuild]
    enableBranchAutoDeletion: Optional[EnableBranchAutoDeletion]
    enableBasicAuth: Optional[EnableBasicAuth]
    basicAuthCredentials: Optional[BasicAuthCredentials]
    customRules: Optional[CustomRules]
    buildSpec: Optional[BuildSpec]
    customHeaders: Optional[CustomHeaders]
    enableAutoBranchCreation: Optional[EnableAutoBranchCreation]
    autoBranchCreationPatterns: Optional[AutoBranchCreationPatterns]
    autoBranchCreationConfig: Optional[AutoBranchCreationConfig]
    repository: Optional[Repository]
    oauthToken: Optional[OauthToken]
    accessToken: Optional[AccessToken]


class UpdateAppResult(TypedDict, total=False):
    app: App


class UpdateBranchRequest(ServiceRequest):
    appId: AppId
    branchName: BranchName
    description: Optional[Description]
    framework: Optional[Framework]
    stage: Optional[Stage]
    enableNotification: Optional[EnableNotification]
    enableAutoBuild: Optional[EnableAutoBuild]
    environmentVariables: Optional[EnvironmentVariables]
    basicAuthCredentials: Optional[BasicAuthCredentials]
    enableBasicAuth: Optional[EnableBasicAuth]
    enablePerformanceMode: Optional[EnablePerformanceMode]
    buildSpec: Optional[BuildSpec]
    ttl: Optional[TTL]
    displayName: Optional[DisplayName]
    enablePullRequestPreview: Optional[EnablePullRequestPreview]
    pullRequestEnvironmentName: Optional[PullRequestEnvironmentName]
    backendEnvironmentArn: Optional[BackendEnvironmentArn]


class UpdateBranchResult(TypedDict, total=False):
    branch: Branch


class UpdateDomainAssociationRequest(ServiceRequest):
    appId: AppId
    domainName: DomainName
    enableAutoSubDomain: Optional[EnableAutoSubDomain]
    subDomainSettings: Optional[SubDomainSettings]
    autoSubDomainCreationPatterns: Optional[AutoSubDomainCreationPatterns]
    autoSubDomainIAMRole: Optional[AutoSubDomainIAMRole]


class UpdateDomainAssociationResult(TypedDict, total=False):
    domainAssociation: DomainAssociation


class UpdateWebhookRequest(ServiceRequest):
    webhookId: WebhookId
    branchName: Optional[BranchName]
    description: Optional[Description]


class UpdateWebhookResult(TypedDict, total=False):
    webhook: Webhook


class AmplifyApi:

    service = "amplify"
    version = "2017-07-25"

    @handler("CreateApp")
    def create_app(
        self,
        context: RequestContext,
        name: Name,
        description: Description = None,
        repository: Repository = None,
        platform: Platform = None,
        iam_service_role_arn: ServiceRoleArn = None,
        oauth_token: OauthToken = None,
        access_token: AccessToken = None,
        environment_variables: EnvironmentVariables = None,
        enable_branch_auto_build: EnableBranchAutoBuild = None,
        enable_branch_auto_deletion: EnableBranchAutoDeletion = None,
        enable_basic_auth: EnableBasicAuth = None,
        basic_auth_credentials: BasicAuthCredentials = None,
        custom_rules: CustomRules = None,
        tags: TagMap = None,
        build_spec: BuildSpec = None,
        custom_headers: CustomHeaders = None,
        enable_auto_branch_creation: EnableAutoBranchCreation = None,
        auto_branch_creation_patterns: AutoBranchCreationPatterns = None,
        auto_branch_creation_config: AutoBranchCreationConfig = None,
    ) -> CreateAppResult:
        raise NotImplementedError

    @handler("CreateBackendEnvironment")
    def create_backend_environment(
        self,
        context: RequestContext,
        app_id: AppId,
        environment_name: EnvironmentName,
        stack_name: StackName = None,
        deployment_artifacts: DeploymentArtifacts = None,
    ) -> CreateBackendEnvironmentResult:
        raise NotImplementedError

    @handler("CreateBranch")
    def create_branch(
        self,
        context: RequestContext,
        app_id: AppId,
        branch_name: BranchName,
        description: Description = None,
        stage: Stage = None,
        framework: Framework = None,
        enable_notification: EnableNotification = None,
        enable_auto_build: EnableAutoBuild = None,
        environment_variables: EnvironmentVariables = None,
        basic_auth_credentials: BasicAuthCredentials = None,
        enable_basic_auth: EnableBasicAuth = None,
        enable_performance_mode: EnablePerformanceMode = None,
        tags: TagMap = None,
        build_spec: BuildSpec = None,
        ttl: TTL = None,
        display_name: DisplayName = None,
        enable_pull_request_preview: EnablePullRequestPreview = None,
        pull_request_environment_name: PullRequestEnvironmentName = None,
        backend_environment_arn: BackendEnvironmentArn = None,
    ) -> CreateBranchResult:
        raise NotImplementedError

    @handler("CreateDeployment")
    def create_deployment(
        self,
        context: RequestContext,
        app_id: AppId,
        branch_name: BranchName,
        file_map: FileMap = None,
    ) -> CreateDeploymentResult:
        raise NotImplementedError

    @handler("CreateDomainAssociation")
    def create_domain_association(
        self,
        context: RequestContext,
        app_id: AppId,
        domain_name: DomainName,
        sub_domain_settings: SubDomainSettings,
        enable_auto_sub_domain: EnableAutoSubDomain = None,
        auto_sub_domain_creation_patterns: AutoSubDomainCreationPatterns = None,
        auto_sub_domain_iam_role: AutoSubDomainIAMRole = None,
    ) -> CreateDomainAssociationResult:
        raise NotImplementedError

    @handler("CreateWebhook")
    def create_webhook(
        self,
        context: RequestContext,
        app_id: AppId,
        branch_name: BranchName,
        description: Description = None,
    ) -> CreateWebhookResult:
        raise NotImplementedError

    @handler("DeleteApp")
    def delete_app(self, context: RequestContext, app_id: AppId) -> DeleteAppResult:
        raise NotImplementedError

    @handler("DeleteBackendEnvironment")
    def delete_backend_environment(
        self, context: RequestContext, app_id: AppId, environment_name: EnvironmentName
    ) -> DeleteBackendEnvironmentResult:
        raise NotImplementedError

    @handler("DeleteBranch")
    def delete_branch(
        self, context: RequestContext, app_id: AppId, branch_name: BranchName
    ) -> DeleteBranchResult:
        raise NotImplementedError

    @handler("DeleteDomainAssociation")
    def delete_domain_association(
        self, context: RequestContext, app_id: AppId, domain_name: DomainName
    ) -> DeleteDomainAssociationResult:
        raise NotImplementedError

    @handler("DeleteJob")
    def delete_job(
        self, context: RequestContext, app_id: AppId, branch_name: BranchName, job_id: JobId
    ) -> DeleteJobResult:
        raise NotImplementedError

    @handler("DeleteWebhook")
    def delete_webhook(self, context: RequestContext, webhook_id: WebhookId) -> DeleteWebhookResult:
        raise NotImplementedError

    @handler("GenerateAccessLogs")
    def generate_access_logs(
        self,
        context: RequestContext,
        domain_name: DomainName,
        app_id: AppId,
        start_time: StartTime = None,
        end_time: EndTime = None,
    ) -> GenerateAccessLogsResult:
        raise NotImplementedError

    @handler("GetApp")
    def get_app(self, context: RequestContext, app_id: AppId) -> GetAppResult:
        raise NotImplementedError

    @handler("GetArtifactUrl")
    def get_artifact_url(
        self, context: RequestContext, artifact_id: ArtifactId
    ) -> GetArtifactUrlResult:
        raise NotImplementedError

    @handler("GetBackendEnvironment")
    def get_backend_environment(
        self, context: RequestContext, app_id: AppId, environment_name: EnvironmentName
    ) -> GetBackendEnvironmentResult:
        raise NotImplementedError

    @handler("GetBranch")
    def get_branch(
        self, context: RequestContext, app_id: AppId, branch_name: BranchName
    ) -> GetBranchResult:
        raise NotImplementedError

    @handler("GetDomainAssociation")
    def get_domain_association(
        self, context: RequestContext, app_id: AppId, domain_name: DomainName
    ) -> GetDomainAssociationResult:
        raise NotImplementedError

    @handler("GetJob")
    def get_job(
        self, context: RequestContext, app_id: AppId, branch_name: BranchName, job_id: JobId
    ) -> GetJobResult:
        raise NotImplementedError

    @handler("GetWebhook")
    def get_webhook(self, context: RequestContext, webhook_id: WebhookId) -> GetWebhookResult:
        raise NotImplementedError

    @handler("ListApps")
    def list_apps(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListAppsResult:
        raise NotImplementedError

    @handler("ListArtifacts")
    def list_artifacts(
        self,
        context: RequestContext,
        app_id: AppId,
        branch_name: BranchName,
        job_id: JobId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListArtifactsResult:
        raise NotImplementedError

    @handler("ListBackendEnvironments")
    def list_backend_environments(
        self,
        context: RequestContext,
        app_id: AppId,
        environment_name: EnvironmentName = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListBackendEnvironmentsResult:
        raise NotImplementedError

    @handler("ListBranches")
    def list_branches(
        self,
        context: RequestContext,
        app_id: AppId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListBranchesResult:
        raise NotImplementedError

    @handler("ListDomainAssociations")
    def list_domain_associations(
        self,
        context: RequestContext,
        app_id: AppId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListDomainAssociationsResult:
        raise NotImplementedError

    @handler("ListJobs")
    def list_jobs(
        self,
        context: RequestContext,
        app_id: AppId,
        branch_name: BranchName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListJobsResult:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: ResourceArn
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListWebhooks")
    def list_webhooks(
        self,
        context: RequestContext,
        app_id: AppId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListWebhooksResult:
        raise NotImplementedError

    @handler("StartDeployment")
    def start_deployment(
        self,
        context: RequestContext,
        app_id: AppId,
        branch_name: BranchName,
        job_id: JobId = None,
        source_url: SourceUrl = None,
    ) -> StartDeploymentResult:
        raise NotImplementedError

    @handler("StartJob")
    def start_job(
        self,
        context: RequestContext,
        app_id: AppId,
        branch_name: BranchName,
        job_type: JobType,
        job_id: JobId = None,
        job_reason: JobReason = None,
        commit_id: CommitId = None,
        commit_message: CommitMessage = None,
        commit_time: CommitTime = None,
    ) -> StartJobResult:
        raise NotImplementedError

    @handler("StopJob")
    def stop_job(
        self, context: RequestContext, app_id: AppId, branch_name: BranchName, job_id: JobId
    ) -> StopJobResult:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tags: TagMap
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateApp")
    def update_app(
        self,
        context: RequestContext,
        app_id: AppId,
        name: Name = None,
        description: Description = None,
        platform: Platform = None,
        iam_service_role_arn: ServiceRoleArn = None,
        environment_variables: EnvironmentVariables = None,
        enable_branch_auto_build: EnableAutoBuild = None,
        enable_branch_auto_deletion: EnableBranchAutoDeletion = None,
        enable_basic_auth: EnableBasicAuth = None,
        basic_auth_credentials: BasicAuthCredentials = None,
        custom_rules: CustomRules = None,
        build_spec: BuildSpec = None,
        custom_headers: CustomHeaders = None,
        enable_auto_branch_creation: EnableAutoBranchCreation = None,
        auto_branch_creation_patterns: AutoBranchCreationPatterns = None,
        auto_branch_creation_config: AutoBranchCreationConfig = None,
        repository: Repository = None,
        oauth_token: OauthToken = None,
        access_token: AccessToken = None,
    ) -> UpdateAppResult:
        raise NotImplementedError

    @handler("UpdateBranch")
    def update_branch(
        self,
        context: RequestContext,
        app_id: AppId,
        branch_name: BranchName,
        description: Description = None,
        framework: Framework = None,
        stage: Stage = None,
        enable_notification: EnableNotification = None,
        enable_auto_build: EnableAutoBuild = None,
        environment_variables: EnvironmentVariables = None,
        basic_auth_credentials: BasicAuthCredentials = None,
        enable_basic_auth: EnableBasicAuth = None,
        enable_performance_mode: EnablePerformanceMode = None,
        build_spec: BuildSpec = None,
        ttl: TTL = None,
        display_name: DisplayName = None,
        enable_pull_request_preview: EnablePullRequestPreview = None,
        pull_request_environment_name: PullRequestEnvironmentName = None,
        backend_environment_arn: BackendEnvironmentArn = None,
    ) -> UpdateBranchResult:
        raise NotImplementedError

    @handler("UpdateDomainAssociation")
    def update_domain_association(
        self,
        context: RequestContext,
        app_id: AppId,
        domain_name: DomainName,
        enable_auto_sub_domain: EnableAutoSubDomain = None,
        sub_domain_settings: SubDomainSettings = None,
        auto_sub_domain_creation_patterns: AutoSubDomainCreationPatterns = None,
        auto_sub_domain_iam_role: AutoSubDomainIAMRole = None,
    ) -> UpdateDomainAssociationResult:
        raise NotImplementedError

    @handler("UpdateWebhook")
    def update_webhook(
        self,
        context: RequestContext,
        webhook_id: WebhookId,
        branch_name: BranchName = None,
        description: Description = None,
    ) -> UpdateWebhookResult:
        raise NotImplementedError
