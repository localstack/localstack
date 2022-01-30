import sys
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

MaxItems = int
_boolean = bool
_double = float
_integer = int
_string = str


class Capability(str):
    CAPABILITY_IAM = "CAPABILITY_IAM"
    CAPABILITY_NAMED_IAM = "CAPABILITY_NAMED_IAM"
    CAPABILITY_AUTO_EXPAND = "CAPABILITY_AUTO_EXPAND"
    CAPABILITY_RESOURCE_POLICY = "CAPABILITY_RESOURCE_POLICY"


class Status(str):
    PREPARING = "PREPARING"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"


class BadRequestException(ServiceException):
    ErrorCode: Optional[_string]
    Message: Optional[_string]


class ConflictException(ServiceException):
    ErrorCode: Optional[_string]
    Message: Optional[_string]


class ForbiddenException(ServiceException):
    ErrorCode: Optional[_string]
    Message: Optional[_string]


class InternalServerErrorException(ServiceException):
    ErrorCode: Optional[_string]
    Message: Optional[_string]


class NotFoundException(ServiceException):
    ErrorCode: Optional[_string]
    Message: Optional[_string]


class TooManyRequestsException(ServiceException):
    ErrorCode: Optional[_string]
    Message: Optional[_string]


_listOfCapability = List[Capability]
_listOf__string = List[_string]


class ParameterDefinition(TypedDict, total=False):
    AllowedPattern: Optional[_string]
    AllowedValues: Optional[_listOf__string]
    ConstraintDescription: Optional[_string]
    DefaultValue: Optional[_string]
    Description: Optional[_string]
    MaxLength: Optional[_integer]
    MaxValue: Optional[_integer]
    MinLength: Optional[_integer]
    MinValue: Optional[_integer]
    Name: _string
    NoEcho: Optional[_boolean]
    ReferencedByResources: _listOf__string
    Type: Optional[_string]


_listOfParameterDefinition = List[ParameterDefinition]


class Version(TypedDict, total=False):
    ApplicationId: _string
    CreationTime: _string
    ParameterDefinitions: _listOfParameterDefinition
    RequiredCapabilities: _listOfCapability
    ResourcesSupported: _boolean
    SemanticVersion: _string
    SourceCodeArchiveUrl: Optional[_string]
    SourceCodeUrl: Optional[_string]
    TemplateUrl: _string


class Application(TypedDict, total=False):
    ApplicationId: _string
    Author: _string
    CreationTime: Optional[_string]
    Description: _string
    HomePageUrl: Optional[_string]
    IsVerifiedAuthor: Optional[_boolean]
    Labels: Optional[_listOf__string]
    LicenseUrl: Optional[_string]
    Name: _string
    ReadmeUrl: Optional[_string]
    SpdxLicenseId: Optional[_string]
    VerifiedAuthorUrl: Optional[_string]
    Version: Optional[Version]


class ApplicationDependencySummary(TypedDict, total=False):
    ApplicationId: _string
    SemanticVersion: _string


_listOfApplicationDependencySummary = List[ApplicationDependencySummary]


class ApplicationDependencyPage(TypedDict, total=False):
    Dependencies: _listOfApplicationDependencySummary
    NextToken: Optional[_string]


class ApplicationSummary(TypedDict, total=False):
    ApplicationId: _string
    Author: _string
    CreationTime: Optional[_string]
    Description: _string
    HomePageUrl: Optional[_string]
    Labels: Optional[_listOf__string]
    Name: _string
    SpdxLicenseId: Optional[_string]


_listOfApplicationSummary = List[ApplicationSummary]


class ApplicationPage(TypedDict, total=False):
    Applications: _listOfApplicationSummary
    NextToken: Optional[_string]


class ApplicationPolicyStatement(TypedDict, total=False):
    Actions: _listOf__string
    PrincipalOrgIDs: Optional[_listOf__string]
    Principals: _listOf__string
    StatementId: Optional[_string]


_listOfApplicationPolicyStatement = List[ApplicationPolicyStatement]


class ApplicationPolicy(TypedDict, total=False):
    Statements: _listOfApplicationPolicyStatement


class VersionSummary(TypedDict, total=False):
    ApplicationId: _string
    CreationTime: _string
    SemanticVersion: _string
    SourceCodeUrl: Optional[_string]


_listOfVersionSummary = List[VersionSummary]


class ApplicationVersionPage(TypedDict, total=False):
    NextToken: Optional[_string]
    Versions: _listOfVersionSummary


class ChangeSetDetails(TypedDict, total=False):
    ApplicationId: _string
    ChangeSetId: _string
    SemanticVersion: _string
    StackId: _string


class CreateApplicationInput(TypedDict, total=False):
    Author: _string
    Description: _string
    HomePageUrl: Optional[_string]
    Labels: Optional[_listOf__string]
    LicenseBody: Optional[_string]
    LicenseUrl: Optional[_string]
    Name: _string
    ReadmeBody: Optional[_string]
    ReadmeUrl: Optional[_string]
    SemanticVersion: Optional[_string]
    SourceCodeArchiveUrl: Optional[_string]
    SourceCodeUrl: Optional[_string]
    SpdxLicenseId: Optional[_string]
    TemplateBody: Optional[_string]
    TemplateUrl: Optional[_string]


class CreateApplicationRequest(ServiceRequest):
    Author: _string
    Description: _string
    HomePageUrl: Optional[_string]
    Labels: Optional[_listOf__string]
    LicenseBody: Optional[_string]
    LicenseUrl: Optional[_string]
    Name: _string
    ReadmeBody: Optional[_string]
    ReadmeUrl: Optional[_string]
    SemanticVersion: Optional[_string]
    SourceCodeArchiveUrl: Optional[_string]
    SourceCodeUrl: Optional[_string]
    SpdxLicenseId: Optional[_string]
    TemplateBody: Optional[_string]
    TemplateUrl: Optional[_string]


class CreateApplicationResponse(TypedDict, total=False):
    ApplicationId: Optional[_string]
    Author: Optional[_string]
    CreationTime: Optional[_string]
    Description: Optional[_string]
    HomePageUrl: Optional[_string]
    IsVerifiedAuthor: Optional[_boolean]
    Labels: Optional[_listOf__string]
    LicenseUrl: Optional[_string]
    Name: Optional[_string]
    ReadmeUrl: Optional[_string]
    SpdxLicenseId: Optional[_string]
    VerifiedAuthorUrl: Optional[_string]
    Version: Optional[Version]


class CreateApplicationVersionInput(TypedDict, total=False):
    SourceCodeArchiveUrl: Optional[_string]
    SourceCodeUrl: Optional[_string]
    TemplateBody: Optional[_string]
    TemplateUrl: Optional[_string]


class CreateApplicationVersionRequest(ServiceRequest):
    ApplicationId: _string
    SemanticVersion: _string
    SourceCodeArchiveUrl: Optional[_string]
    SourceCodeUrl: Optional[_string]
    TemplateBody: Optional[_string]
    TemplateUrl: Optional[_string]


class CreateApplicationVersionResponse(TypedDict, total=False):
    ApplicationId: Optional[_string]
    CreationTime: Optional[_string]
    ParameterDefinitions: Optional[_listOfParameterDefinition]
    RequiredCapabilities: Optional[_listOfCapability]
    ResourcesSupported: Optional[_boolean]
    SemanticVersion: Optional[_string]
    SourceCodeArchiveUrl: Optional[_string]
    SourceCodeUrl: Optional[_string]
    TemplateUrl: Optional[_string]


class Tag(TypedDict, total=False):
    Key: _string
    Value: _string


_listOfTag = List[Tag]


class RollbackTrigger(TypedDict, total=False):
    Arn: _string
    Type: _string


_listOfRollbackTrigger = List[RollbackTrigger]


class RollbackConfiguration(TypedDict, total=False):
    MonitoringTimeInMinutes: Optional[_integer]
    RollbackTriggers: Optional[_listOfRollbackTrigger]


class ParameterValue(TypedDict, total=False):
    Name: _string
    Value: _string


_listOfParameterValue = List[ParameterValue]


class CreateCloudFormationChangeSetInput(TypedDict, total=False):
    Capabilities: Optional[_listOf__string]
    ChangeSetName: Optional[_string]
    ClientToken: Optional[_string]
    Description: Optional[_string]
    NotificationArns: Optional[_listOf__string]
    ParameterOverrides: Optional[_listOfParameterValue]
    ResourceTypes: Optional[_listOf__string]
    RollbackConfiguration: Optional[RollbackConfiguration]
    SemanticVersion: Optional[_string]
    StackName: _string
    Tags: Optional[_listOfTag]
    TemplateId: Optional[_string]


class CreateCloudFormationChangeSetRequest(ServiceRequest):
    ApplicationId: _string
    Capabilities: Optional[_listOf__string]
    ChangeSetName: Optional[_string]
    ClientToken: Optional[_string]
    Description: Optional[_string]
    NotificationArns: Optional[_listOf__string]
    ParameterOverrides: Optional[_listOfParameterValue]
    ResourceTypes: Optional[_listOf__string]
    RollbackConfiguration: Optional[RollbackConfiguration]
    SemanticVersion: Optional[_string]
    StackName: _string
    Tags: Optional[_listOfTag]
    TemplateId: Optional[_string]


class CreateCloudFormationChangeSetResponse(TypedDict, total=False):
    ApplicationId: Optional[_string]
    ChangeSetId: Optional[_string]
    SemanticVersion: Optional[_string]
    StackId: Optional[_string]


class CreateCloudFormationTemplateRequest(ServiceRequest):
    ApplicationId: _string
    SemanticVersion: Optional[_string]


class CreateCloudFormationTemplateResponse(TypedDict, total=False):
    ApplicationId: Optional[_string]
    CreationTime: Optional[_string]
    ExpirationTime: Optional[_string]
    SemanticVersion: Optional[_string]
    Status: Optional[Status]
    TemplateId: Optional[_string]
    TemplateUrl: Optional[_string]


class DeleteApplicationRequest(ServiceRequest):
    ApplicationId: _string


class GetApplicationPolicyRequest(ServiceRequest):
    ApplicationId: _string


class GetApplicationPolicyResponse(TypedDict, total=False):
    Statements: Optional[_listOfApplicationPolicyStatement]


class GetApplicationRequest(ServiceRequest):
    ApplicationId: _string
    SemanticVersion: Optional[_string]


class GetApplicationResponse(TypedDict, total=False):
    ApplicationId: Optional[_string]
    Author: Optional[_string]
    CreationTime: Optional[_string]
    Description: Optional[_string]
    HomePageUrl: Optional[_string]
    IsVerifiedAuthor: Optional[_boolean]
    Labels: Optional[_listOf__string]
    LicenseUrl: Optional[_string]
    Name: Optional[_string]
    ReadmeUrl: Optional[_string]
    SpdxLicenseId: Optional[_string]
    VerifiedAuthorUrl: Optional[_string]
    Version: Optional[Version]


class GetCloudFormationTemplateRequest(ServiceRequest):
    ApplicationId: _string
    TemplateId: _string


class GetCloudFormationTemplateResponse(TypedDict, total=False):
    ApplicationId: Optional[_string]
    CreationTime: Optional[_string]
    ExpirationTime: Optional[_string]
    SemanticVersion: Optional[_string]
    Status: Optional[Status]
    TemplateId: Optional[_string]
    TemplateUrl: Optional[_string]


class ListApplicationDependenciesRequest(ServiceRequest):
    ApplicationId: _string
    MaxItems: Optional[MaxItems]
    NextToken: Optional[_string]
    SemanticVersion: Optional[_string]


class ListApplicationDependenciesResponse(TypedDict, total=False):
    Dependencies: Optional[_listOfApplicationDependencySummary]
    NextToken: Optional[_string]


class ListApplicationVersionsRequest(ServiceRequest):
    ApplicationId: _string
    MaxItems: Optional[MaxItems]
    NextToken: Optional[_string]


class ListApplicationVersionsResponse(TypedDict, total=False):
    NextToken: Optional[_string]
    Versions: Optional[_listOfVersionSummary]


class ListApplicationsRequest(ServiceRequest):
    MaxItems: Optional[MaxItems]
    NextToken: Optional[_string]


class ListApplicationsResponse(TypedDict, total=False):
    Applications: Optional[_listOfApplicationSummary]
    NextToken: Optional[_string]


class PutApplicationPolicyRequest(ServiceRequest):
    ApplicationId: _string
    Statements: _listOfApplicationPolicyStatement


class PutApplicationPolicyResponse(TypedDict, total=False):
    Statements: Optional[_listOfApplicationPolicyStatement]


class TemplateDetails(TypedDict, total=False):
    ApplicationId: _string
    CreationTime: _string
    ExpirationTime: _string
    SemanticVersion: _string
    Status: Status
    TemplateId: _string
    TemplateUrl: _string


class UnshareApplicationInput(TypedDict, total=False):
    OrganizationId: _string


class UnshareApplicationRequest(ServiceRequest):
    ApplicationId: _string
    OrganizationId: _string


class UpdateApplicationInput(TypedDict, total=False):
    Author: Optional[_string]
    Description: Optional[_string]
    HomePageUrl: Optional[_string]
    Labels: Optional[_listOf__string]
    ReadmeBody: Optional[_string]
    ReadmeUrl: Optional[_string]


class UpdateApplicationRequest(ServiceRequest):
    ApplicationId: _string
    Author: Optional[_string]
    Description: Optional[_string]
    HomePageUrl: Optional[_string]
    Labels: Optional[_listOf__string]
    ReadmeBody: Optional[_string]
    ReadmeUrl: Optional[_string]


class UpdateApplicationResponse(TypedDict, total=False):
    ApplicationId: Optional[_string]
    Author: Optional[_string]
    CreationTime: Optional[_string]
    Description: Optional[_string]
    HomePageUrl: Optional[_string]
    IsVerifiedAuthor: Optional[_boolean]
    Labels: Optional[_listOf__string]
    LicenseUrl: Optional[_string]
    Name: Optional[_string]
    ReadmeUrl: Optional[_string]
    SpdxLicenseId: Optional[_string]
    VerifiedAuthorUrl: Optional[_string]
    Version: Optional[Version]


_long = int


class ServerlessrepoApi:

    service = "serverlessrepo"
    version = "2017-09-08"

    @handler("CreateApplication")
    def create_application(
        self,
        context: RequestContext,
        description: _string,
        name: _string,
        author: _string,
        home_page_url: _string = None,
        labels: _listOf__string = None,
        license_body: _string = None,
        license_url: _string = None,
        readme_body: _string = None,
        readme_url: _string = None,
        semantic_version: _string = None,
        source_code_archive_url: _string = None,
        source_code_url: _string = None,
        spdx_license_id: _string = None,
        template_body: _string = None,
        template_url: _string = None,
    ) -> CreateApplicationResponse:
        raise NotImplementedError

    @handler("CreateApplicationVersion")
    def create_application_version(
        self,
        context: RequestContext,
        application_id: _string,
        semantic_version: _string,
        source_code_archive_url: _string = None,
        source_code_url: _string = None,
        template_body: _string = None,
        template_url: _string = None,
    ) -> CreateApplicationVersionResponse:
        raise NotImplementedError

    @handler("CreateCloudFormationChangeSet")
    def create_cloud_formation_change_set(
        self,
        context: RequestContext,
        application_id: _string,
        stack_name: _string,
        capabilities: _listOf__string = None,
        change_set_name: _string = None,
        client_token: _string = None,
        description: _string = None,
        notification_arns: _listOf__string = None,
        parameter_overrides: _listOfParameterValue = None,
        resource_types: _listOf__string = None,
        rollback_configuration: RollbackConfiguration = None,
        semantic_version: _string = None,
        tags: _listOfTag = None,
        template_id: _string = None,
    ) -> CreateCloudFormationChangeSetResponse:
        raise NotImplementedError

    @handler("CreateCloudFormationTemplate")
    def create_cloud_formation_template(
        self, context: RequestContext, application_id: _string, semantic_version: _string = None
    ) -> CreateCloudFormationTemplateResponse:
        raise NotImplementedError

    @handler("DeleteApplication")
    def delete_application(self, context: RequestContext, application_id: _string) -> None:
        raise NotImplementedError

    @handler("GetApplication")
    def get_application(
        self, context: RequestContext, application_id: _string, semantic_version: _string = None
    ) -> GetApplicationResponse:
        raise NotImplementedError

    @handler("GetApplicationPolicy")
    def get_application_policy(
        self, context: RequestContext, application_id: _string
    ) -> GetApplicationPolicyResponse:
        raise NotImplementedError

    @handler("GetCloudFormationTemplate")
    def get_cloud_formation_template(
        self, context: RequestContext, application_id: _string, template_id: _string
    ) -> GetCloudFormationTemplateResponse:
        raise NotImplementedError

    @handler("ListApplicationDependencies")
    def list_application_dependencies(
        self,
        context: RequestContext,
        application_id: _string,
        max_items: MaxItems = None,
        next_token: _string = None,
        semantic_version: _string = None,
    ) -> ListApplicationDependenciesResponse:
        raise NotImplementedError

    @handler("ListApplicationVersions")
    def list_application_versions(
        self,
        context: RequestContext,
        application_id: _string,
        max_items: MaxItems = None,
        next_token: _string = None,
    ) -> ListApplicationVersionsResponse:
        raise NotImplementedError

    @handler("ListApplications")
    def list_applications(
        self, context: RequestContext, max_items: MaxItems = None, next_token: _string = None
    ) -> ListApplicationsResponse:
        raise NotImplementedError

    @handler("PutApplicationPolicy")
    def put_application_policy(
        self,
        context: RequestContext,
        application_id: _string,
        statements: _listOfApplicationPolicyStatement,
    ) -> PutApplicationPolicyResponse:
        raise NotImplementedError

    @handler("UnshareApplication")
    def unshare_application(
        self, context: RequestContext, application_id: _string, organization_id: _string
    ) -> None:
        raise NotImplementedError

    @handler("UpdateApplication")
    def update_application(
        self,
        context: RequestContext,
        application_id: _string,
        author: _string = None,
        description: _string = None,
        home_page_url: _string = None,
        labels: _listOf__string = None,
        readme_body: _string = None,
        readme_url: _string = None,
    ) -> UpdateApplicationResponse:
        raise NotImplementedError
