import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccountId = str
AdditionalData = str
ApprovalRuleContent = str
ApprovalRuleId = str
ApprovalRuleName = str
ApprovalRuleTemplateContent = str
ApprovalRuleTemplateDescription = str
ApprovalRuleTemplateId = str
ApprovalRuleTemplateName = str
Approved = bool
Arn = str
BranchName = str
CapitalBoolean = bool
ClientRequestToken = str
CloneUrlHttp = str
CloneUrlSsh = str
CommentId = str
CommitId = str
CommitName = str
Content = str
Count = int
Date = str
Description = str
Email = str
ErrorCode = str
ErrorMessage = str
ExceptionName = str
HunkContent = str
IsCommentDeleted = bool
IsContentConflict = bool
IsFileModeConflict = bool
IsHunkConflict = bool
IsMergeable = bool
IsMerged = bool
IsMove = bool
IsObjectTypeConflict = bool
KeepEmptyFolders = bool
Limit = int
LineNumber = int
MaxResults = int
Message = str
Mode = str
Name = str
NextToken = str
NumberOfConflicts = int
ObjectId = str
Overridden = bool
Path = str
PullRequestId = str
ReactionEmoji = str
ReactionShortCode = str
ReactionUnicode = str
ReactionValue = str
ReferenceName = str
RepositoryDescription = str
RepositoryId = str
RepositoryName = str
RepositoryTriggerCustomData = str
RepositoryTriggerExecutionFailureMessage = str
RepositoryTriggerName = str
RepositoryTriggersConfigurationId = str
ResourceArn = str
RevisionId = str
RuleContentSha256 = str
TagKey = str
TagValue = str
Title = str


class ApprovalState(str):
    APPROVE = "APPROVE"
    REVOKE = "REVOKE"


class ChangeTypeEnum(str):
    A = "A"
    M = "M"
    D = "D"


class ConflictDetailLevelTypeEnum(str):
    FILE_LEVEL = "FILE_LEVEL"
    LINE_LEVEL = "LINE_LEVEL"


class ConflictResolutionStrategyTypeEnum(str):
    NONE = "NONE"
    ACCEPT_SOURCE = "ACCEPT_SOURCE"
    ACCEPT_DESTINATION = "ACCEPT_DESTINATION"
    AUTOMERGE = "AUTOMERGE"


class FileModeTypeEnum(str):
    EXECUTABLE = "EXECUTABLE"
    NORMAL = "NORMAL"
    SYMLINK = "SYMLINK"


class MergeOptionTypeEnum(str):
    FAST_FORWARD_MERGE = "FAST_FORWARD_MERGE"
    SQUASH_MERGE = "SQUASH_MERGE"
    THREE_WAY_MERGE = "THREE_WAY_MERGE"


class ObjectTypeEnum(str):
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"
    GIT_LINK = "GIT_LINK"
    SYMBOLIC_LINK = "SYMBOLIC_LINK"


class OrderEnum(str):
    ascending = "ascending"
    descending = "descending"


class OverrideStatus(str):
    OVERRIDE = "OVERRIDE"
    REVOKE = "REVOKE"


class PullRequestEventType(str):
    PULL_REQUEST_CREATED = "PULL_REQUEST_CREATED"
    PULL_REQUEST_STATUS_CHANGED = "PULL_REQUEST_STATUS_CHANGED"
    PULL_REQUEST_SOURCE_REFERENCE_UPDATED = "PULL_REQUEST_SOURCE_REFERENCE_UPDATED"
    PULL_REQUEST_MERGE_STATE_CHANGED = "PULL_REQUEST_MERGE_STATE_CHANGED"
    PULL_REQUEST_APPROVAL_RULE_CREATED = "PULL_REQUEST_APPROVAL_RULE_CREATED"
    PULL_REQUEST_APPROVAL_RULE_UPDATED = "PULL_REQUEST_APPROVAL_RULE_UPDATED"
    PULL_REQUEST_APPROVAL_RULE_DELETED = "PULL_REQUEST_APPROVAL_RULE_DELETED"
    PULL_REQUEST_APPROVAL_RULE_OVERRIDDEN = "PULL_REQUEST_APPROVAL_RULE_OVERRIDDEN"
    PULL_REQUEST_APPROVAL_STATE_CHANGED = "PULL_REQUEST_APPROVAL_STATE_CHANGED"


class PullRequestStatusEnum(str):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class RelativeFileVersionEnum(str):
    BEFORE = "BEFORE"
    AFTER = "AFTER"


class ReplacementTypeEnum(str):
    KEEP_BASE = "KEEP_BASE"
    KEEP_SOURCE = "KEEP_SOURCE"
    KEEP_DESTINATION = "KEEP_DESTINATION"
    USE_NEW_CONTENT = "USE_NEW_CONTENT"


class RepositoryTriggerEventEnum(str):
    all = "all"
    updateReference = "updateReference"
    createReference = "createReference"
    deleteReference = "deleteReference"


class SortByEnum(str):
    repositoryName = "repositoryName"
    lastModifiedDate = "lastModifiedDate"


class ActorDoesNotExistException(ServiceException):
    pass


class ApprovalRuleContentRequiredException(ServiceException):
    pass


class ApprovalRuleDoesNotExistException(ServiceException):
    pass


class ApprovalRuleNameAlreadyExistsException(ServiceException):
    pass


class ApprovalRuleNameRequiredException(ServiceException):
    pass


class ApprovalRuleTemplateContentRequiredException(ServiceException):
    pass


class ApprovalRuleTemplateDoesNotExistException(ServiceException):
    pass


class ApprovalRuleTemplateInUseException(ServiceException):
    pass


class ApprovalRuleTemplateNameAlreadyExistsException(ServiceException):
    pass


class ApprovalRuleTemplateNameRequiredException(ServiceException):
    pass


class ApprovalStateRequiredException(ServiceException):
    pass


class AuthorDoesNotExistException(ServiceException):
    pass


class BeforeCommitIdAndAfterCommitIdAreSameException(ServiceException):
    pass


class BlobIdDoesNotExistException(ServiceException):
    pass


class BlobIdRequiredException(ServiceException):
    pass


class BranchDoesNotExistException(ServiceException):
    pass


class BranchNameExistsException(ServiceException):
    pass


class BranchNameIsTagNameException(ServiceException):
    pass


class BranchNameRequiredException(ServiceException):
    pass


class CannotDeleteApprovalRuleFromTemplateException(ServiceException):
    pass


class CannotModifyApprovalRuleFromTemplateException(ServiceException):
    pass


class ClientRequestTokenRequiredException(ServiceException):
    pass


class CommentContentRequiredException(ServiceException):
    pass


class CommentContentSizeLimitExceededException(ServiceException):
    pass


class CommentDeletedException(ServiceException):
    pass


class CommentDoesNotExistException(ServiceException):
    pass


class CommentIdRequiredException(ServiceException):
    pass


class CommentNotCreatedByCallerException(ServiceException):
    pass


class CommitDoesNotExistException(ServiceException):
    pass


class CommitIdDoesNotExistException(ServiceException):
    pass


class CommitIdRequiredException(ServiceException):
    pass


class CommitIdsLimitExceededException(ServiceException):
    pass


class CommitIdsListRequiredException(ServiceException):
    pass


class CommitMessageLengthExceededException(ServiceException):
    pass


class CommitRequiredException(ServiceException):
    pass


class ConcurrentReferenceUpdateException(ServiceException):
    pass


class DefaultBranchCannotBeDeletedException(ServiceException):
    pass


class DirectoryNameConflictsWithFileNameException(ServiceException):
    pass


class EncryptionIntegrityChecksFailedException(ServiceException):
    pass


class EncryptionKeyAccessDeniedException(ServiceException):
    pass


class EncryptionKeyDisabledException(ServiceException):
    pass


class EncryptionKeyNotFoundException(ServiceException):
    pass


class EncryptionKeyUnavailableException(ServiceException):
    pass


class FileContentAndSourceFileSpecifiedException(ServiceException):
    pass


class FileContentRequiredException(ServiceException):
    pass


class FileContentSizeLimitExceededException(ServiceException):
    pass


class FileDoesNotExistException(ServiceException):
    pass


class FileEntryRequiredException(ServiceException):
    pass


class FileModeRequiredException(ServiceException):
    pass


class FileNameConflictsWithDirectoryNameException(ServiceException):
    pass


class FilePathConflictsWithSubmodulePathException(ServiceException):
    pass


class FileTooLargeException(ServiceException):
    pass


class FolderContentSizeLimitExceededException(ServiceException):
    pass


class FolderDoesNotExistException(ServiceException):
    pass


class IdempotencyParameterMismatchException(ServiceException):
    pass


class InvalidActorArnException(ServiceException):
    pass


class InvalidApprovalRuleContentException(ServiceException):
    pass


class InvalidApprovalRuleNameException(ServiceException):
    pass


class InvalidApprovalRuleTemplateContentException(ServiceException):
    pass


class InvalidApprovalRuleTemplateDescriptionException(ServiceException):
    pass


class InvalidApprovalRuleTemplateNameException(ServiceException):
    pass


class InvalidApprovalStateException(ServiceException):
    pass


class InvalidAuthorArnException(ServiceException):
    pass


class InvalidBlobIdException(ServiceException):
    pass


class InvalidBranchNameException(ServiceException):
    pass


class InvalidClientRequestTokenException(ServiceException):
    pass


class InvalidCommentIdException(ServiceException):
    pass


class InvalidCommitException(ServiceException):
    pass


class InvalidCommitIdException(ServiceException):
    pass


class InvalidConflictDetailLevelException(ServiceException):
    pass


class InvalidConflictResolutionException(ServiceException):
    pass


class InvalidConflictResolutionStrategyException(ServiceException):
    pass


class InvalidContinuationTokenException(ServiceException):
    pass


class InvalidDeletionParameterException(ServiceException):
    pass


class InvalidDescriptionException(ServiceException):
    pass


class InvalidDestinationCommitSpecifierException(ServiceException):
    pass


class InvalidEmailException(ServiceException):
    pass


class InvalidFileLocationException(ServiceException):
    pass


class InvalidFileModeException(ServiceException):
    pass


class InvalidFilePositionException(ServiceException):
    pass


class InvalidMaxConflictFilesException(ServiceException):
    pass


class InvalidMaxMergeHunksException(ServiceException):
    pass


class InvalidMaxResultsException(ServiceException):
    pass


class InvalidMergeOptionException(ServiceException):
    pass


class InvalidOrderException(ServiceException):
    pass


class InvalidOverrideStatusException(ServiceException):
    pass


class InvalidParentCommitIdException(ServiceException):
    pass


class InvalidPathException(ServiceException):
    pass


class InvalidPullRequestEventTypeException(ServiceException):
    pass


class InvalidPullRequestIdException(ServiceException):
    pass


class InvalidPullRequestStatusException(ServiceException):
    pass


class InvalidPullRequestStatusUpdateException(ServiceException):
    pass


class InvalidReactionUserArnException(ServiceException):
    pass


class InvalidReactionValueException(ServiceException):
    pass


class InvalidReferenceNameException(ServiceException):
    pass


class InvalidRelativeFileVersionEnumException(ServiceException):
    pass


class InvalidReplacementContentException(ServiceException):
    pass


class InvalidReplacementTypeException(ServiceException):
    pass


class InvalidRepositoryDescriptionException(ServiceException):
    pass


class InvalidRepositoryNameException(ServiceException):
    pass


class InvalidRepositoryTriggerBranchNameException(ServiceException):
    pass


class InvalidRepositoryTriggerCustomDataException(ServiceException):
    pass


class InvalidRepositoryTriggerDestinationArnException(ServiceException):
    pass


class InvalidRepositoryTriggerEventsException(ServiceException):
    pass


class InvalidRepositoryTriggerNameException(ServiceException):
    pass


class InvalidRepositoryTriggerRegionException(ServiceException):
    pass


class InvalidResourceArnException(ServiceException):
    pass


class InvalidRevisionIdException(ServiceException):
    pass


class InvalidRuleContentSha256Exception(ServiceException):
    pass


class InvalidSortByException(ServiceException):
    pass


class InvalidSourceCommitSpecifierException(ServiceException):
    pass


class InvalidSystemTagUsageException(ServiceException):
    pass


class InvalidTagKeysListException(ServiceException):
    pass


class InvalidTagsMapException(ServiceException):
    pass


class InvalidTargetBranchException(ServiceException):
    pass


class InvalidTargetException(ServiceException):
    pass


class InvalidTargetsException(ServiceException):
    pass


class InvalidTitleException(ServiceException):
    pass


class ManualMergeRequiredException(ServiceException):
    pass


class MaximumBranchesExceededException(ServiceException):
    pass


class MaximumConflictResolutionEntriesExceededException(ServiceException):
    pass


class MaximumFileContentToLoadExceededException(ServiceException):
    pass


class MaximumFileEntriesExceededException(ServiceException):
    pass


class MaximumItemsToCompareExceededException(ServiceException):
    pass


class MaximumNumberOfApprovalsExceededException(ServiceException):
    pass


class MaximumOpenPullRequestsExceededException(ServiceException):
    pass


class MaximumRepositoryNamesExceededException(ServiceException):
    pass


class MaximumRepositoryTriggersExceededException(ServiceException):
    pass


class MaximumRuleTemplatesAssociatedWithRepositoryException(ServiceException):
    pass


class MergeOptionRequiredException(ServiceException):
    pass


class MultipleConflictResolutionEntriesException(ServiceException):
    pass


class MultipleRepositoriesInPullRequestException(ServiceException):
    pass


class NameLengthExceededException(ServiceException):
    pass


class NoChangeException(ServiceException):
    pass


class NumberOfRuleTemplatesExceededException(ServiceException):
    pass


class NumberOfRulesExceededException(ServiceException):
    pass


class OverrideAlreadySetException(ServiceException):
    pass


class OverrideStatusRequiredException(ServiceException):
    pass


class ParentCommitDoesNotExistException(ServiceException):
    pass


class ParentCommitIdOutdatedException(ServiceException):
    pass


class ParentCommitIdRequiredException(ServiceException):
    pass


class PathDoesNotExistException(ServiceException):
    pass


class PathRequiredException(ServiceException):
    pass


class PullRequestAlreadyClosedException(ServiceException):
    pass


class PullRequestApprovalRulesNotSatisfiedException(ServiceException):
    pass


class PullRequestCannotBeApprovedByAuthorException(ServiceException):
    pass


class PullRequestDoesNotExistException(ServiceException):
    pass


class PullRequestIdRequiredException(ServiceException):
    pass


class PullRequestStatusRequiredException(ServiceException):
    pass


class PutFileEntryConflictException(ServiceException):
    pass


class ReactionLimitExceededException(ServiceException):
    pass


class ReactionValueRequiredException(ServiceException):
    pass


class ReferenceDoesNotExistException(ServiceException):
    pass


class ReferenceNameRequiredException(ServiceException):
    pass


class ReferenceTypeNotSupportedException(ServiceException):
    pass


class ReplacementContentRequiredException(ServiceException):
    pass


class ReplacementTypeRequiredException(ServiceException):
    pass


class RepositoryDoesNotExistException(ServiceException):
    pass


class RepositoryLimitExceededException(ServiceException):
    pass


class RepositoryNameExistsException(ServiceException):
    pass


class RepositoryNameRequiredException(ServiceException):
    pass


class RepositoryNamesRequiredException(ServiceException):
    pass


class RepositoryNotAssociatedWithPullRequestException(ServiceException):
    pass


class RepositoryTriggerBranchNameListRequiredException(ServiceException):
    pass


class RepositoryTriggerDestinationArnRequiredException(ServiceException):
    pass


class RepositoryTriggerEventsListRequiredException(ServiceException):
    pass


class RepositoryTriggerNameRequiredException(ServiceException):
    pass


class RepositoryTriggersListRequiredException(ServiceException):
    pass


class ResourceArnRequiredException(ServiceException):
    pass


class RestrictedSourceFileException(ServiceException):
    pass


class RevisionIdRequiredException(ServiceException):
    pass


class RevisionNotCurrentException(ServiceException):
    pass


class SameFileContentException(ServiceException):
    pass


class SamePathRequestException(ServiceException):
    pass


class SourceAndDestinationAreSameException(ServiceException):
    pass


class SourceFileOrContentRequiredException(ServiceException):
    pass


class TagKeysListRequiredException(ServiceException):
    pass


class TagPolicyException(ServiceException):
    pass


class TagsMapRequiredException(ServiceException):
    pass


class TargetRequiredException(ServiceException):
    pass


class TargetsRequiredException(ServiceException):
    pass


class TipOfSourceReferenceIsDifferentException(ServiceException):
    pass


class TipsDivergenceExceededException(ServiceException):
    pass


class TitleRequiredException(ServiceException):
    pass


class TooManyTagsException(ServiceException):
    pass


class Approval(TypedDict, total=False):
    userArn: Optional[Arn]
    approvalState: Optional[ApprovalState]


ApprovalList = List[Approval]


class OriginApprovalRuleTemplate(TypedDict, total=False):
    approvalRuleTemplateId: Optional[ApprovalRuleTemplateId]
    approvalRuleTemplateName: Optional[ApprovalRuleTemplateName]


CreationDate = datetime
LastModifiedDate = datetime


class ApprovalRule(TypedDict, total=False):
    approvalRuleId: Optional[ApprovalRuleId]
    approvalRuleName: Optional[ApprovalRuleName]
    approvalRuleContent: Optional[ApprovalRuleContent]
    ruleContentSha256: Optional[RuleContentSha256]
    lastModifiedDate: Optional[LastModifiedDate]
    creationDate: Optional[CreationDate]
    lastModifiedUser: Optional[Arn]
    originApprovalRuleTemplate: Optional[OriginApprovalRuleTemplate]


class ApprovalRuleEventMetadata(TypedDict, total=False):
    approvalRuleName: Optional[ApprovalRuleName]
    approvalRuleId: Optional[ApprovalRuleId]
    approvalRuleContent: Optional[ApprovalRuleContent]


class ApprovalRuleOverriddenEventMetadata(TypedDict, total=False):
    revisionId: Optional[RevisionId]
    overrideStatus: Optional[OverrideStatus]


class ApprovalRuleTemplate(TypedDict, total=False):
    approvalRuleTemplateId: Optional[ApprovalRuleTemplateId]
    approvalRuleTemplateName: Optional[ApprovalRuleTemplateName]
    approvalRuleTemplateDescription: Optional[ApprovalRuleTemplateDescription]
    approvalRuleTemplateContent: Optional[ApprovalRuleTemplateContent]
    ruleContentSha256: Optional[RuleContentSha256]
    lastModifiedDate: Optional[LastModifiedDate]
    creationDate: Optional[CreationDate]
    lastModifiedUser: Optional[Arn]


ApprovalRuleTemplateNameList = List[ApprovalRuleTemplateName]
ApprovalRulesList = List[ApprovalRule]
ApprovalRulesNotSatisfiedList = List[ApprovalRuleName]
ApprovalRulesSatisfiedList = List[ApprovalRuleName]


class ApprovalStateChangedEventMetadata(TypedDict, total=False):
    revisionId: Optional[RevisionId]
    approvalStatus: Optional[ApprovalState]


class AssociateApprovalRuleTemplateWithRepositoryInput(ServiceRequest):
    approvalRuleTemplateName: ApprovalRuleTemplateName
    repositoryName: RepositoryName


class BatchAssociateApprovalRuleTemplateWithRepositoriesError(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    errorCode: Optional[ErrorCode]
    errorMessage: Optional[ErrorMessage]


BatchAssociateApprovalRuleTemplateWithRepositoriesErrorsList = List[
    BatchAssociateApprovalRuleTemplateWithRepositoriesError
]
RepositoryNameList = List[RepositoryName]


class BatchAssociateApprovalRuleTemplateWithRepositoriesInput(ServiceRequest):
    approvalRuleTemplateName: ApprovalRuleTemplateName
    repositoryNames: RepositoryNameList


class BatchAssociateApprovalRuleTemplateWithRepositoriesOutput(TypedDict, total=False):
    associatedRepositoryNames: RepositoryNameList
    errors: BatchAssociateApprovalRuleTemplateWithRepositoriesErrorsList


class BatchDescribeMergeConflictsError(TypedDict, total=False):
    filePath: Path
    exceptionName: ExceptionName
    message: Message


BatchDescribeMergeConflictsErrors = List[BatchDescribeMergeConflictsError]
FilePaths = List[Path]


class BatchDescribeMergeConflictsInput(ServiceRequest):
    repositoryName: RepositoryName
    destinationCommitSpecifier: CommitName
    sourceCommitSpecifier: CommitName
    mergeOption: MergeOptionTypeEnum
    maxMergeHunks: Optional[MaxResults]
    maxConflictFiles: Optional[MaxResults]
    filePaths: Optional[FilePaths]
    conflictDetailLevel: Optional[ConflictDetailLevelTypeEnum]
    conflictResolutionStrategy: Optional[ConflictResolutionStrategyTypeEnum]
    nextToken: Optional[NextToken]


class MergeHunkDetail(TypedDict, total=False):
    startLine: Optional[LineNumber]
    endLine: Optional[LineNumber]
    hunkContent: Optional[HunkContent]


class MergeHunk(TypedDict, total=False):
    isConflict: Optional[IsHunkConflict]
    source: Optional[MergeHunkDetail]
    destination: Optional[MergeHunkDetail]
    base: Optional[MergeHunkDetail]


MergeHunks = List[MergeHunk]


class MergeOperations(TypedDict, total=False):
    source: Optional[ChangeTypeEnum]
    destination: Optional[ChangeTypeEnum]


class IsBinaryFile(TypedDict, total=False):
    source: Optional[CapitalBoolean]
    destination: Optional[CapitalBoolean]
    base: Optional[CapitalBoolean]


class ObjectTypes(TypedDict, total=False):
    source: Optional[ObjectTypeEnum]
    destination: Optional[ObjectTypeEnum]
    base: Optional[ObjectTypeEnum]


class FileModes(TypedDict, total=False):
    source: Optional[FileModeTypeEnum]
    destination: Optional[FileModeTypeEnum]
    base: Optional[FileModeTypeEnum]


FileSize = int


class FileSizes(TypedDict, total=False):
    source: Optional[FileSize]
    destination: Optional[FileSize]
    base: Optional[FileSize]


class ConflictMetadata(TypedDict, total=False):
    filePath: Optional[Path]
    fileSizes: Optional[FileSizes]
    fileModes: Optional[FileModes]
    objectTypes: Optional[ObjectTypes]
    numberOfConflicts: Optional[NumberOfConflicts]
    isBinaryFile: Optional[IsBinaryFile]
    contentConflict: Optional[IsContentConflict]
    fileModeConflict: Optional[IsFileModeConflict]
    objectTypeConflict: Optional[IsObjectTypeConflict]
    mergeOperations: Optional[MergeOperations]


class Conflict(TypedDict, total=False):
    conflictMetadata: Optional[ConflictMetadata]
    mergeHunks: Optional[MergeHunks]


Conflicts = List[Conflict]


class BatchDescribeMergeConflictsOutput(TypedDict, total=False):
    conflicts: Conflicts
    nextToken: Optional[NextToken]
    errors: Optional[BatchDescribeMergeConflictsErrors]
    destinationCommitId: ObjectId
    sourceCommitId: ObjectId
    baseCommitId: Optional[ObjectId]


class BatchDisassociateApprovalRuleTemplateFromRepositoriesError(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    errorCode: Optional[ErrorCode]
    errorMessage: Optional[ErrorMessage]


BatchDisassociateApprovalRuleTemplateFromRepositoriesErrorsList = List[
    BatchDisassociateApprovalRuleTemplateFromRepositoriesError
]


class BatchDisassociateApprovalRuleTemplateFromRepositoriesInput(ServiceRequest):
    approvalRuleTemplateName: ApprovalRuleTemplateName
    repositoryNames: RepositoryNameList


class BatchDisassociateApprovalRuleTemplateFromRepositoriesOutput(TypedDict, total=False):
    disassociatedRepositoryNames: RepositoryNameList
    errors: BatchDisassociateApprovalRuleTemplateFromRepositoriesErrorsList


class BatchGetCommitsError(TypedDict, total=False):
    commitId: Optional[ObjectId]
    errorCode: Optional[ErrorCode]
    errorMessage: Optional[ErrorMessage]


BatchGetCommitsErrorsList = List[BatchGetCommitsError]
CommitIdsInputList = List[ObjectId]


class BatchGetCommitsInput(ServiceRequest):
    commitIds: CommitIdsInputList
    repositoryName: RepositoryName


class UserInfo(TypedDict, total=False):
    name: Optional[Name]
    email: Optional[Email]
    date: Optional[Date]


ParentList = List[ObjectId]


class Commit(TypedDict, total=False):
    commitId: Optional[ObjectId]
    treeId: Optional[ObjectId]
    parents: Optional[ParentList]
    message: Optional[Message]
    author: Optional[UserInfo]
    committer: Optional[UserInfo]
    additionalData: Optional[AdditionalData]


CommitObjectsList = List[Commit]


class BatchGetCommitsOutput(TypedDict, total=False):
    commits: Optional[CommitObjectsList]
    errors: Optional[BatchGetCommitsErrorsList]


class BatchGetRepositoriesInput(ServiceRequest):
    repositoryNames: RepositoryNameList


RepositoryNotFoundList = List[RepositoryName]


class RepositoryMetadata(TypedDict, total=False):
    accountId: Optional[AccountId]
    repositoryId: Optional[RepositoryId]
    repositoryName: Optional[RepositoryName]
    repositoryDescription: Optional[RepositoryDescription]
    defaultBranch: Optional[BranchName]
    lastModifiedDate: Optional[LastModifiedDate]
    creationDate: Optional[CreationDate]
    cloneUrlHttp: Optional[CloneUrlHttp]
    cloneUrlSsh: Optional[CloneUrlSsh]
    Arn: Optional[Arn]


RepositoryMetadataList = List[RepositoryMetadata]


class BatchGetRepositoriesOutput(TypedDict, total=False):
    repositories: Optional[RepositoryMetadataList]
    repositoriesNotFound: Optional[RepositoryNotFoundList]


class BlobMetadata(TypedDict, total=False):
    blobId: Optional[ObjectId]
    path: Optional[Path]
    mode: Optional[Mode]


class BranchInfo(TypedDict, total=False):
    branchName: Optional[BranchName]
    commitId: Optional[CommitId]


BranchNameList = List[BranchName]
CallerReactions = List[ReactionValue]
ReactionCountsMap = Dict[ReactionValue, Count]


class Comment(TypedDict, total=False):
    commentId: Optional[CommentId]
    content: Optional[Content]
    inReplyTo: Optional[CommentId]
    creationDate: Optional[CreationDate]
    lastModifiedDate: Optional[LastModifiedDate]
    authorArn: Optional[Arn]
    deleted: Optional[IsCommentDeleted]
    clientRequestToken: Optional[ClientRequestToken]
    callerReactions: Optional[CallerReactions]
    reactionCounts: Optional[ReactionCountsMap]


Comments = List[Comment]
Position = int


class Location(TypedDict, total=False):
    filePath: Optional[Path]
    filePosition: Optional[Position]
    relativeFileVersion: Optional[RelativeFileVersionEnum]


class CommentsForComparedCommit(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    beforeCommitId: Optional[CommitId]
    afterCommitId: Optional[CommitId]
    beforeBlobId: Optional[ObjectId]
    afterBlobId: Optional[ObjectId]
    location: Optional[Location]
    comments: Optional[Comments]


CommentsForComparedCommitData = List[CommentsForComparedCommit]


class CommentsForPullRequest(TypedDict, total=False):
    pullRequestId: Optional[PullRequestId]
    repositoryName: Optional[RepositoryName]
    beforeCommitId: Optional[CommitId]
    afterCommitId: Optional[CommitId]
    beforeBlobId: Optional[ObjectId]
    afterBlobId: Optional[ObjectId]
    location: Optional[Location]
    comments: Optional[Comments]


CommentsForPullRequestData = List[CommentsForPullRequest]
ConflictMetadataList = List[ConflictMetadata]


class SetFileModeEntry(TypedDict, total=False):
    filePath: Path
    fileMode: FileModeTypeEnum


SetFileModeEntries = List[SetFileModeEntry]


class DeleteFileEntry(TypedDict, total=False):
    filePath: Path


DeleteFileEntries = List[DeleteFileEntry]
FileContent = bytes


class ReplaceContentEntry(TypedDict, total=False):
    filePath: Path
    replacementType: ReplacementTypeEnum
    content: Optional[FileContent]
    fileMode: Optional[FileModeTypeEnum]


ReplaceContentEntries = List[ReplaceContentEntry]


class ConflictResolution(TypedDict, total=False):
    replaceContents: Optional[ReplaceContentEntries]
    deleteFiles: Optional[DeleteFileEntries]
    setFileModes: Optional[SetFileModeEntries]


class CreateApprovalRuleTemplateInput(ServiceRequest):
    approvalRuleTemplateName: ApprovalRuleTemplateName
    approvalRuleTemplateContent: ApprovalRuleTemplateContent
    approvalRuleTemplateDescription: Optional[ApprovalRuleTemplateDescription]


class CreateApprovalRuleTemplateOutput(TypedDict, total=False):
    approvalRuleTemplate: ApprovalRuleTemplate


class CreateBranchInput(ServiceRequest):
    repositoryName: RepositoryName
    branchName: BranchName
    commitId: CommitId


class SourceFileSpecifier(TypedDict, total=False):
    filePath: Path
    isMove: Optional[IsMove]


class PutFileEntry(TypedDict, total=False):
    filePath: Path
    fileMode: Optional[FileModeTypeEnum]
    fileContent: Optional[FileContent]
    sourceFile: Optional[SourceFileSpecifier]


PutFileEntries = List[PutFileEntry]


class CreateCommitInput(ServiceRequest):
    repositoryName: RepositoryName
    branchName: BranchName
    parentCommitId: Optional[CommitId]
    authorName: Optional[Name]
    email: Optional[Email]
    commitMessage: Optional[Message]
    keepEmptyFolders: Optional[KeepEmptyFolders]
    putFiles: Optional[PutFileEntries]
    deleteFiles: Optional[DeleteFileEntries]
    setFileModes: Optional[SetFileModeEntries]


class FileMetadata(TypedDict, total=False):
    absolutePath: Optional[Path]
    blobId: Optional[ObjectId]
    fileMode: Optional[FileModeTypeEnum]


FilesMetadata = List[FileMetadata]


class CreateCommitOutput(TypedDict, total=False):
    commitId: Optional[ObjectId]
    treeId: Optional[ObjectId]
    filesAdded: Optional[FilesMetadata]
    filesUpdated: Optional[FilesMetadata]
    filesDeleted: Optional[FilesMetadata]


class CreatePullRequestApprovalRuleInput(ServiceRequest):
    pullRequestId: PullRequestId
    approvalRuleName: ApprovalRuleName
    approvalRuleContent: ApprovalRuleContent


class CreatePullRequestApprovalRuleOutput(TypedDict, total=False):
    approvalRule: ApprovalRule


class Target(TypedDict, total=False):
    repositoryName: RepositoryName
    sourceReference: ReferenceName
    destinationReference: Optional[ReferenceName]


TargetList = List[Target]


class CreatePullRequestInput(ServiceRequest):
    title: Title
    description: Optional[Description]
    targets: TargetList
    clientRequestToken: Optional[ClientRequestToken]


class MergeMetadata(TypedDict, total=False):
    isMerged: Optional[IsMerged]
    mergedBy: Optional[Arn]
    mergeCommitId: Optional[CommitId]
    mergeOption: Optional[MergeOptionTypeEnum]


class PullRequestTarget(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    sourceReference: Optional[ReferenceName]
    destinationReference: Optional[ReferenceName]
    destinationCommit: Optional[CommitId]
    sourceCommit: Optional[CommitId]
    mergeBase: Optional[CommitId]
    mergeMetadata: Optional[MergeMetadata]


PullRequestTargetList = List[PullRequestTarget]


class PullRequest(TypedDict, total=False):
    pullRequestId: Optional[PullRequestId]
    title: Optional[Title]
    description: Optional[Description]
    lastActivityDate: Optional[LastModifiedDate]
    creationDate: Optional[CreationDate]
    pullRequestStatus: Optional[PullRequestStatusEnum]
    authorArn: Optional[Arn]
    pullRequestTargets: Optional[PullRequestTargetList]
    clientRequestToken: Optional[ClientRequestToken]
    revisionId: Optional[RevisionId]
    approvalRules: Optional[ApprovalRulesList]


class CreatePullRequestOutput(TypedDict, total=False):
    pullRequest: PullRequest


TagsMap = Dict[TagKey, TagValue]


class CreateRepositoryInput(ServiceRequest):
    repositoryName: RepositoryName
    repositoryDescription: Optional[RepositoryDescription]
    tags: Optional[TagsMap]


class CreateRepositoryOutput(TypedDict, total=False):
    repositoryMetadata: Optional[RepositoryMetadata]


class CreateUnreferencedMergeCommitInput(ServiceRequest):
    repositoryName: RepositoryName
    sourceCommitSpecifier: CommitName
    destinationCommitSpecifier: CommitName
    mergeOption: MergeOptionTypeEnum
    conflictDetailLevel: Optional[ConflictDetailLevelTypeEnum]
    conflictResolutionStrategy: Optional[ConflictResolutionStrategyTypeEnum]
    authorName: Optional[Name]
    email: Optional[Email]
    commitMessage: Optional[Message]
    keepEmptyFolders: Optional[KeepEmptyFolders]
    conflictResolution: Optional[ConflictResolution]


class CreateUnreferencedMergeCommitOutput(TypedDict, total=False):
    commitId: Optional[ObjectId]
    treeId: Optional[ObjectId]


class DeleteApprovalRuleTemplateInput(ServiceRequest):
    approvalRuleTemplateName: ApprovalRuleTemplateName


class DeleteApprovalRuleTemplateOutput(TypedDict, total=False):
    approvalRuleTemplateId: ApprovalRuleTemplateId


class DeleteBranchInput(ServiceRequest):
    repositoryName: RepositoryName
    branchName: BranchName


class DeleteBranchOutput(TypedDict, total=False):
    deletedBranch: Optional[BranchInfo]


class DeleteCommentContentInput(ServiceRequest):
    commentId: CommentId


class DeleteCommentContentOutput(TypedDict, total=False):
    comment: Optional[Comment]


class DeleteFileInput(ServiceRequest):
    repositoryName: RepositoryName
    branchName: BranchName
    filePath: Path
    parentCommitId: CommitId
    keepEmptyFolders: Optional[KeepEmptyFolders]
    commitMessage: Optional[Message]
    name: Optional[Name]
    email: Optional[Email]


class DeleteFileOutput(TypedDict, total=False):
    commitId: ObjectId
    blobId: ObjectId
    treeId: ObjectId
    filePath: Path


class DeletePullRequestApprovalRuleInput(ServiceRequest):
    pullRequestId: PullRequestId
    approvalRuleName: ApprovalRuleName


class DeletePullRequestApprovalRuleOutput(TypedDict, total=False):
    approvalRuleId: ApprovalRuleId


class DeleteRepositoryInput(ServiceRequest):
    repositoryName: RepositoryName


class DeleteRepositoryOutput(TypedDict, total=False):
    repositoryId: Optional[RepositoryId]


class DescribeMergeConflictsInput(ServiceRequest):
    repositoryName: RepositoryName
    destinationCommitSpecifier: CommitName
    sourceCommitSpecifier: CommitName
    mergeOption: MergeOptionTypeEnum
    maxMergeHunks: Optional[MaxResults]
    filePath: Path
    conflictDetailLevel: Optional[ConflictDetailLevelTypeEnum]
    conflictResolutionStrategy: Optional[ConflictResolutionStrategyTypeEnum]
    nextToken: Optional[NextToken]


class DescribeMergeConflictsOutput(TypedDict, total=False):
    conflictMetadata: ConflictMetadata
    mergeHunks: MergeHunks
    nextToken: Optional[NextToken]
    destinationCommitId: ObjectId
    sourceCommitId: ObjectId
    baseCommitId: Optional[ObjectId]


class DescribePullRequestEventsInput(ServiceRequest):
    pullRequestId: PullRequestId
    pullRequestEventType: Optional[PullRequestEventType]
    actorArn: Optional[Arn]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class PullRequestMergedStateChangedEventMetadata(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    destinationReference: Optional[ReferenceName]
    mergeMetadata: Optional[MergeMetadata]


class PullRequestSourceReferenceUpdatedEventMetadata(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    beforeCommitId: Optional[CommitId]
    afterCommitId: Optional[CommitId]
    mergeBase: Optional[CommitId]


class PullRequestStatusChangedEventMetadata(TypedDict, total=False):
    pullRequestStatus: Optional[PullRequestStatusEnum]


class PullRequestCreatedEventMetadata(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    sourceCommitId: Optional[CommitId]
    destinationCommitId: Optional[CommitId]
    mergeBase: Optional[CommitId]


EventDate = datetime


class PullRequestEvent(TypedDict, total=False):
    pullRequestId: Optional[PullRequestId]
    eventDate: Optional[EventDate]
    pullRequestEventType: Optional[PullRequestEventType]
    actorArn: Optional[Arn]
    pullRequestCreatedEventMetadata: Optional[PullRequestCreatedEventMetadata]
    pullRequestStatusChangedEventMetadata: Optional[PullRequestStatusChangedEventMetadata]
    pullRequestSourceReferenceUpdatedEventMetadata: Optional[
        PullRequestSourceReferenceUpdatedEventMetadata
    ]
    pullRequestMergedStateChangedEventMetadata: Optional[PullRequestMergedStateChangedEventMetadata]
    approvalRuleEventMetadata: Optional[ApprovalRuleEventMetadata]
    approvalStateChangedEventMetadata: Optional[ApprovalStateChangedEventMetadata]
    approvalRuleOverriddenEventMetadata: Optional[ApprovalRuleOverriddenEventMetadata]


PullRequestEventList = List[PullRequestEvent]


class DescribePullRequestEventsOutput(TypedDict, total=False):
    pullRequestEvents: PullRequestEventList
    nextToken: Optional[NextToken]


class Difference(TypedDict, total=False):
    beforeBlob: Optional[BlobMetadata]
    afterBlob: Optional[BlobMetadata]
    changeType: Optional[ChangeTypeEnum]


DifferenceList = List[Difference]


class DisassociateApprovalRuleTemplateFromRepositoryInput(ServiceRequest):
    approvalRuleTemplateName: ApprovalRuleTemplateName
    repositoryName: RepositoryName


class EvaluatePullRequestApprovalRulesInput(ServiceRequest):
    pullRequestId: PullRequestId
    revisionId: RevisionId


class Evaluation(TypedDict, total=False):
    approved: Optional[Approved]
    overridden: Optional[Overridden]
    approvalRulesSatisfied: Optional[ApprovalRulesSatisfiedList]
    approvalRulesNotSatisfied: Optional[ApprovalRulesNotSatisfiedList]


class EvaluatePullRequestApprovalRulesOutput(TypedDict, total=False):
    evaluation: Evaluation


class File(TypedDict, total=False):
    blobId: Optional[ObjectId]
    absolutePath: Optional[Path]
    relativePath: Optional[Path]
    fileMode: Optional[FileModeTypeEnum]


FileList = List[File]


class Folder(TypedDict, total=False):
    treeId: Optional[ObjectId]
    absolutePath: Optional[Path]
    relativePath: Optional[Path]


FolderList = List[Folder]


class GetApprovalRuleTemplateInput(ServiceRequest):
    approvalRuleTemplateName: ApprovalRuleTemplateName


class GetApprovalRuleTemplateOutput(TypedDict, total=False):
    approvalRuleTemplate: ApprovalRuleTemplate


class GetBlobInput(ServiceRequest):
    repositoryName: RepositoryName
    blobId: ObjectId


blob = bytes


class GetBlobOutput(TypedDict, total=False):
    content: blob


class GetBranchInput(ServiceRequest):
    repositoryName: Optional[RepositoryName]
    branchName: Optional[BranchName]


class GetBranchOutput(TypedDict, total=False):
    branch: Optional[BranchInfo]


class GetCommentInput(ServiceRequest):
    commentId: CommentId


class GetCommentOutput(TypedDict, total=False):
    comment: Optional[Comment]


class GetCommentReactionsInput(ServiceRequest):
    commentId: CommentId
    reactionUserArn: Optional[Arn]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


ReactionUsersList = List[Arn]


class ReactionValueFormats(TypedDict, total=False):
    emoji: Optional[ReactionEmoji]
    shortCode: Optional[ReactionShortCode]
    unicode: Optional[ReactionUnicode]


class ReactionForComment(TypedDict, total=False):
    reaction: Optional[ReactionValueFormats]
    reactionUsers: Optional[ReactionUsersList]
    reactionsFromDeletedUsersCount: Optional[Count]


ReactionsForCommentList = List[ReactionForComment]


class GetCommentReactionsOutput(TypedDict, total=False):
    reactionsForComment: ReactionsForCommentList
    nextToken: Optional[NextToken]


class GetCommentsForComparedCommitInput(ServiceRequest):
    repositoryName: RepositoryName
    beforeCommitId: Optional[CommitId]
    afterCommitId: CommitId
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class GetCommentsForComparedCommitOutput(TypedDict, total=False):
    commentsForComparedCommitData: Optional[CommentsForComparedCommitData]
    nextToken: Optional[NextToken]


class GetCommentsForPullRequestInput(ServiceRequest):
    pullRequestId: PullRequestId
    repositoryName: Optional[RepositoryName]
    beforeCommitId: Optional[CommitId]
    afterCommitId: Optional[CommitId]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class GetCommentsForPullRequestOutput(TypedDict, total=False):
    commentsForPullRequestData: Optional[CommentsForPullRequestData]
    nextToken: Optional[NextToken]


class GetCommitInput(ServiceRequest):
    repositoryName: RepositoryName
    commitId: ObjectId


class GetCommitOutput(TypedDict, total=False):
    commit: Commit


class GetDifferencesInput(ServiceRequest):
    repositoryName: RepositoryName
    beforeCommitSpecifier: Optional[CommitName]
    afterCommitSpecifier: CommitName
    beforePath: Optional[Path]
    afterPath: Optional[Path]
    MaxResults: Optional[Limit]
    NextToken: Optional[NextToken]


class GetDifferencesOutput(TypedDict, total=False):
    differences: Optional[DifferenceList]
    NextToken: Optional[NextToken]


class GetFileInput(ServiceRequest):
    repositoryName: RepositoryName
    commitSpecifier: Optional[CommitName]
    filePath: Path


ObjectSize = int


class GetFileOutput(TypedDict, total=False):
    commitId: ObjectId
    blobId: ObjectId
    filePath: Path
    fileMode: FileModeTypeEnum
    fileSize: ObjectSize
    fileContent: FileContent


class GetFolderInput(ServiceRequest):
    repositoryName: RepositoryName
    commitSpecifier: Optional[CommitName]
    folderPath: Path


class SubModule(TypedDict, total=False):
    commitId: Optional[ObjectId]
    absolutePath: Optional[Path]
    relativePath: Optional[Path]


SubModuleList = List[SubModule]


class SymbolicLink(TypedDict, total=False):
    blobId: Optional[ObjectId]
    absolutePath: Optional[Path]
    relativePath: Optional[Path]
    fileMode: Optional[FileModeTypeEnum]


SymbolicLinkList = List[SymbolicLink]


class GetFolderOutput(TypedDict, total=False):
    commitId: ObjectId
    folderPath: Path
    treeId: Optional[ObjectId]
    subFolders: Optional[FolderList]
    files: Optional[FileList]
    symbolicLinks: Optional[SymbolicLinkList]
    subModules: Optional[SubModuleList]


class GetMergeCommitInput(ServiceRequest):
    repositoryName: RepositoryName
    sourceCommitSpecifier: CommitName
    destinationCommitSpecifier: CommitName
    conflictDetailLevel: Optional[ConflictDetailLevelTypeEnum]
    conflictResolutionStrategy: Optional[ConflictResolutionStrategyTypeEnum]


class GetMergeCommitOutput(TypedDict, total=False):
    sourceCommitId: Optional[ObjectId]
    destinationCommitId: Optional[ObjectId]
    baseCommitId: Optional[ObjectId]
    mergedCommitId: Optional[ObjectId]


class GetMergeConflictsInput(ServiceRequest):
    repositoryName: RepositoryName
    destinationCommitSpecifier: CommitName
    sourceCommitSpecifier: CommitName
    mergeOption: MergeOptionTypeEnum
    conflictDetailLevel: Optional[ConflictDetailLevelTypeEnum]
    maxConflictFiles: Optional[MaxResults]
    conflictResolutionStrategy: Optional[ConflictResolutionStrategyTypeEnum]
    nextToken: Optional[NextToken]


class GetMergeConflictsOutput(TypedDict, total=False):
    mergeable: IsMergeable
    destinationCommitId: ObjectId
    sourceCommitId: ObjectId
    baseCommitId: Optional[ObjectId]
    conflictMetadataList: ConflictMetadataList
    nextToken: Optional[NextToken]


class GetMergeOptionsInput(ServiceRequest):
    repositoryName: RepositoryName
    sourceCommitSpecifier: CommitName
    destinationCommitSpecifier: CommitName
    conflictDetailLevel: Optional[ConflictDetailLevelTypeEnum]
    conflictResolutionStrategy: Optional[ConflictResolutionStrategyTypeEnum]


MergeOptions = List[MergeOptionTypeEnum]


class GetMergeOptionsOutput(TypedDict, total=False):
    mergeOptions: MergeOptions
    sourceCommitId: ObjectId
    destinationCommitId: ObjectId
    baseCommitId: ObjectId


class GetPullRequestApprovalStatesInput(ServiceRequest):
    pullRequestId: PullRequestId
    revisionId: RevisionId


class GetPullRequestApprovalStatesOutput(TypedDict, total=False):
    approvals: Optional[ApprovalList]


class GetPullRequestInput(ServiceRequest):
    pullRequestId: PullRequestId


class GetPullRequestOutput(TypedDict, total=False):
    pullRequest: PullRequest


class GetPullRequestOverrideStateInput(ServiceRequest):
    pullRequestId: PullRequestId
    revisionId: RevisionId


class GetPullRequestOverrideStateOutput(TypedDict, total=False):
    overridden: Optional[Overridden]
    overrider: Optional[Arn]


class GetRepositoryInput(ServiceRequest):
    repositoryName: RepositoryName


class GetRepositoryOutput(TypedDict, total=False):
    repositoryMetadata: Optional[RepositoryMetadata]


class GetRepositoryTriggersInput(ServiceRequest):
    repositoryName: RepositoryName


RepositoryTriggerEventList = List[RepositoryTriggerEventEnum]


class RepositoryTrigger(TypedDict, total=False):
    name: RepositoryTriggerName
    destinationArn: Arn
    customData: Optional[RepositoryTriggerCustomData]
    branches: Optional[BranchNameList]
    events: RepositoryTriggerEventList


RepositoryTriggersList = List[RepositoryTrigger]


class GetRepositoryTriggersOutput(TypedDict, total=False):
    configurationId: Optional[RepositoryTriggersConfigurationId]
    triggers: Optional[RepositoryTriggersList]


class ListApprovalRuleTemplatesInput(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListApprovalRuleTemplatesOutput(TypedDict, total=False):
    approvalRuleTemplateNames: Optional[ApprovalRuleTemplateNameList]
    nextToken: Optional[NextToken]


class ListAssociatedApprovalRuleTemplatesForRepositoryInput(ServiceRequest):
    repositoryName: RepositoryName
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListAssociatedApprovalRuleTemplatesForRepositoryOutput(TypedDict, total=False):
    approvalRuleTemplateNames: Optional[ApprovalRuleTemplateNameList]
    nextToken: Optional[NextToken]


class ListBranchesInput(ServiceRequest):
    repositoryName: RepositoryName
    nextToken: Optional[NextToken]


class ListBranchesOutput(TypedDict, total=False):
    branches: Optional[BranchNameList]
    nextToken: Optional[NextToken]


class ListPullRequestsInput(ServiceRequest):
    repositoryName: RepositoryName
    authorArn: Optional[Arn]
    pullRequestStatus: Optional[PullRequestStatusEnum]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


PullRequestIdList = List[PullRequestId]


class ListPullRequestsOutput(TypedDict, total=False):
    pullRequestIds: PullRequestIdList
    nextToken: Optional[NextToken]


class ListRepositoriesForApprovalRuleTemplateInput(ServiceRequest):
    approvalRuleTemplateName: ApprovalRuleTemplateName
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListRepositoriesForApprovalRuleTemplateOutput(TypedDict, total=False):
    repositoryNames: Optional[RepositoryNameList]
    nextToken: Optional[NextToken]


class ListRepositoriesInput(ServiceRequest):
    nextToken: Optional[NextToken]
    sortBy: Optional[SortByEnum]
    order: Optional[OrderEnum]


class RepositoryNameIdPair(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    repositoryId: Optional[RepositoryId]


RepositoryNameIdPairList = List[RepositoryNameIdPair]


class ListRepositoriesOutput(TypedDict, total=False):
    repositories: Optional[RepositoryNameIdPairList]
    nextToken: Optional[NextToken]


class ListTagsForResourceInput(ServiceRequest):
    resourceArn: ResourceArn
    nextToken: Optional[NextToken]


class ListTagsForResourceOutput(TypedDict, total=False):
    tags: Optional[TagsMap]
    nextToken: Optional[NextToken]


class MergeBranchesByFastForwardInput(ServiceRequest):
    repositoryName: RepositoryName
    sourceCommitSpecifier: CommitName
    destinationCommitSpecifier: CommitName
    targetBranch: Optional[BranchName]


class MergeBranchesByFastForwardOutput(TypedDict, total=False):
    commitId: Optional[ObjectId]
    treeId: Optional[ObjectId]


class MergeBranchesBySquashInput(ServiceRequest):
    repositoryName: RepositoryName
    sourceCommitSpecifier: CommitName
    destinationCommitSpecifier: CommitName
    targetBranch: Optional[BranchName]
    conflictDetailLevel: Optional[ConflictDetailLevelTypeEnum]
    conflictResolutionStrategy: Optional[ConflictResolutionStrategyTypeEnum]
    authorName: Optional[Name]
    email: Optional[Email]
    commitMessage: Optional[Message]
    keepEmptyFolders: Optional[KeepEmptyFolders]
    conflictResolution: Optional[ConflictResolution]


class MergeBranchesBySquashOutput(TypedDict, total=False):
    commitId: Optional[ObjectId]
    treeId: Optional[ObjectId]


class MergeBranchesByThreeWayInput(ServiceRequest):
    repositoryName: RepositoryName
    sourceCommitSpecifier: CommitName
    destinationCommitSpecifier: CommitName
    targetBranch: Optional[BranchName]
    conflictDetailLevel: Optional[ConflictDetailLevelTypeEnum]
    conflictResolutionStrategy: Optional[ConflictResolutionStrategyTypeEnum]
    authorName: Optional[Name]
    email: Optional[Email]
    commitMessage: Optional[Message]
    keepEmptyFolders: Optional[KeepEmptyFolders]
    conflictResolution: Optional[ConflictResolution]


class MergeBranchesByThreeWayOutput(TypedDict, total=False):
    commitId: Optional[ObjectId]
    treeId: Optional[ObjectId]


class MergePullRequestByFastForwardInput(ServiceRequest):
    pullRequestId: PullRequestId
    repositoryName: RepositoryName
    sourceCommitId: Optional[ObjectId]


class MergePullRequestByFastForwardOutput(TypedDict, total=False):
    pullRequest: Optional[PullRequest]


class MergePullRequestBySquashInput(ServiceRequest):
    pullRequestId: PullRequestId
    repositoryName: RepositoryName
    sourceCommitId: Optional[ObjectId]
    conflictDetailLevel: Optional[ConflictDetailLevelTypeEnum]
    conflictResolutionStrategy: Optional[ConflictResolutionStrategyTypeEnum]
    commitMessage: Optional[Message]
    authorName: Optional[Name]
    email: Optional[Email]
    keepEmptyFolders: Optional[KeepEmptyFolders]
    conflictResolution: Optional[ConflictResolution]


class MergePullRequestBySquashOutput(TypedDict, total=False):
    pullRequest: Optional[PullRequest]


class MergePullRequestByThreeWayInput(ServiceRequest):
    pullRequestId: PullRequestId
    repositoryName: RepositoryName
    sourceCommitId: Optional[ObjectId]
    conflictDetailLevel: Optional[ConflictDetailLevelTypeEnum]
    conflictResolutionStrategy: Optional[ConflictResolutionStrategyTypeEnum]
    commitMessage: Optional[Message]
    authorName: Optional[Name]
    email: Optional[Email]
    keepEmptyFolders: Optional[KeepEmptyFolders]
    conflictResolution: Optional[ConflictResolution]


class MergePullRequestByThreeWayOutput(TypedDict, total=False):
    pullRequest: Optional[PullRequest]


class OverridePullRequestApprovalRulesInput(ServiceRequest):
    pullRequestId: PullRequestId
    revisionId: RevisionId
    overrideStatus: OverrideStatus


class PostCommentForComparedCommitInput(ServiceRequest):
    repositoryName: RepositoryName
    beforeCommitId: Optional[CommitId]
    afterCommitId: CommitId
    location: Optional[Location]
    content: Content
    clientRequestToken: Optional[ClientRequestToken]


class PostCommentForComparedCommitOutput(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    beforeCommitId: Optional[CommitId]
    afterCommitId: Optional[CommitId]
    beforeBlobId: Optional[ObjectId]
    afterBlobId: Optional[ObjectId]
    location: Optional[Location]
    comment: Optional[Comment]


class PostCommentForPullRequestInput(ServiceRequest):
    pullRequestId: PullRequestId
    repositoryName: RepositoryName
    beforeCommitId: CommitId
    afterCommitId: CommitId
    location: Optional[Location]
    content: Content
    clientRequestToken: Optional[ClientRequestToken]


class PostCommentForPullRequestOutput(TypedDict, total=False):
    repositoryName: Optional[RepositoryName]
    pullRequestId: Optional[PullRequestId]
    beforeCommitId: Optional[CommitId]
    afterCommitId: Optional[CommitId]
    beforeBlobId: Optional[ObjectId]
    afterBlobId: Optional[ObjectId]
    location: Optional[Location]
    comment: Optional[Comment]


class PostCommentReplyInput(ServiceRequest):
    inReplyTo: CommentId
    clientRequestToken: Optional[ClientRequestToken]
    content: Content


class PostCommentReplyOutput(TypedDict, total=False):
    comment: Optional[Comment]


class PutCommentReactionInput(ServiceRequest):
    commentId: CommentId
    reactionValue: ReactionValue


class PutFileInput(ServiceRequest):
    repositoryName: RepositoryName
    branchName: BranchName
    fileContent: FileContent
    filePath: Path
    fileMode: Optional[FileModeTypeEnum]
    parentCommitId: Optional[CommitId]
    commitMessage: Optional[Message]
    name: Optional[Name]
    email: Optional[Email]


class PutFileOutput(TypedDict, total=False):
    commitId: ObjectId
    blobId: ObjectId
    treeId: ObjectId


class PutRepositoryTriggersInput(ServiceRequest):
    repositoryName: RepositoryName
    triggers: RepositoryTriggersList


class PutRepositoryTriggersOutput(TypedDict, total=False):
    configurationId: Optional[RepositoryTriggersConfigurationId]


class RepositoryTriggerExecutionFailure(TypedDict, total=False):
    trigger: Optional[RepositoryTriggerName]
    failureMessage: Optional[RepositoryTriggerExecutionFailureMessage]


RepositoryTriggerExecutionFailureList = List[RepositoryTriggerExecutionFailure]
RepositoryTriggerNameList = List[RepositoryTriggerName]
TagKeysList = List[TagKey]


class TagResourceInput(ServiceRequest):
    resourceArn: ResourceArn
    tags: TagsMap


class TestRepositoryTriggersInput(ServiceRequest):
    repositoryName: RepositoryName
    triggers: RepositoryTriggersList


class TestRepositoryTriggersOutput(TypedDict, total=False):
    successfulExecutions: Optional[RepositoryTriggerNameList]
    failedExecutions: Optional[RepositoryTriggerExecutionFailureList]


class UntagResourceInput(ServiceRequest):
    resourceArn: ResourceArn
    tagKeys: TagKeysList


class UpdateApprovalRuleTemplateContentInput(ServiceRequest):
    approvalRuleTemplateName: ApprovalRuleTemplateName
    newRuleContent: ApprovalRuleTemplateContent
    existingRuleContentSha256: Optional[RuleContentSha256]


class UpdateApprovalRuleTemplateContentOutput(TypedDict, total=False):
    approvalRuleTemplate: ApprovalRuleTemplate


class UpdateApprovalRuleTemplateDescriptionInput(ServiceRequest):
    approvalRuleTemplateName: ApprovalRuleTemplateName
    approvalRuleTemplateDescription: ApprovalRuleTemplateDescription


class UpdateApprovalRuleTemplateDescriptionOutput(TypedDict, total=False):
    approvalRuleTemplate: ApprovalRuleTemplate


class UpdateApprovalRuleTemplateNameInput(ServiceRequest):
    oldApprovalRuleTemplateName: ApprovalRuleTemplateName
    newApprovalRuleTemplateName: ApprovalRuleTemplateName


class UpdateApprovalRuleTemplateNameOutput(TypedDict, total=False):
    approvalRuleTemplate: ApprovalRuleTemplate


class UpdateCommentInput(ServiceRequest):
    commentId: CommentId
    content: Content


class UpdateCommentOutput(TypedDict, total=False):
    comment: Optional[Comment]


class UpdateDefaultBranchInput(ServiceRequest):
    repositoryName: RepositoryName
    defaultBranchName: BranchName


class UpdatePullRequestApprovalRuleContentInput(ServiceRequest):
    pullRequestId: PullRequestId
    approvalRuleName: ApprovalRuleName
    existingRuleContentSha256: Optional[RuleContentSha256]
    newRuleContent: ApprovalRuleContent


class UpdatePullRequestApprovalRuleContentOutput(TypedDict, total=False):
    approvalRule: ApprovalRule


class UpdatePullRequestApprovalStateInput(ServiceRequest):
    pullRequestId: PullRequestId
    revisionId: RevisionId
    approvalState: ApprovalState


class UpdatePullRequestDescriptionInput(ServiceRequest):
    pullRequestId: PullRequestId
    description: Description


class UpdatePullRequestDescriptionOutput(TypedDict, total=False):
    pullRequest: PullRequest


class UpdatePullRequestStatusInput(ServiceRequest):
    pullRequestId: PullRequestId
    pullRequestStatus: PullRequestStatusEnum


class UpdatePullRequestStatusOutput(TypedDict, total=False):
    pullRequest: PullRequest


class UpdatePullRequestTitleInput(ServiceRequest):
    pullRequestId: PullRequestId
    title: Title


class UpdatePullRequestTitleOutput(TypedDict, total=False):
    pullRequest: PullRequest


class UpdateRepositoryDescriptionInput(ServiceRequest):
    repositoryName: RepositoryName
    repositoryDescription: Optional[RepositoryDescription]


class UpdateRepositoryNameInput(ServiceRequest):
    oldName: RepositoryName
    newName: RepositoryName


class CodecommitApi:

    service = "codecommit"
    version = "2015-04-13"

    @handler("AssociateApprovalRuleTemplateWithRepository")
    def associate_approval_rule_template_with_repository(
        self,
        context: RequestContext,
        approval_rule_template_name: ApprovalRuleTemplateName,
        repository_name: RepositoryName,
    ) -> None:
        raise NotImplementedError

    @handler("BatchAssociateApprovalRuleTemplateWithRepositories")
    def batch_associate_approval_rule_template_with_repositories(
        self,
        context: RequestContext,
        approval_rule_template_name: ApprovalRuleTemplateName,
        repository_names: RepositoryNameList,
    ) -> BatchAssociateApprovalRuleTemplateWithRepositoriesOutput:
        raise NotImplementedError

    @handler("BatchDescribeMergeConflicts")
    def batch_describe_merge_conflicts(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        destination_commit_specifier: CommitName,
        source_commit_specifier: CommitName,
        merge_option: MergeOptionTypeEnum,
        max_merge_hunks: MaxResults = None,
        max_conflict_files: MaxResults = None,
        file_paths: FilePaths = None,
        conflict_detail_level: ConflictDetailLevelTypeEnum = None,
        conflict_resolution_strategy: ConflictResolutionStrategyTypeEnum = None,
        next_token: NextToken = None,
    ) -> BatchDescribeMergeConflictsOutput:
        raise NotImplementedError

    @handler("BatchDisassociateApprovalRuleTemplateFromRepositories")
    def batch_disassociate_approval_rule_template_from_repositories(
        self,
        context: RequestContext,
        approval_rule_template_name: ApprovalRuleTemplateName,
        repository_names: RepositoryNameList,
    ) -> BatchDisassociateApprovalRuleTemplateFromRepositoriesOutput:
        raise NotImplementedError

    @handler("BatchGetCommits")
    def batch_get_commits(
        self,
        context: RequestContext,
        commit_ids: CommitIdsInputList,
        repository_name: RepositoryName,
    ) -> BatchGetCommitsOutput:
        raise NotImplementedError

    @handler("BatchGetRepositories")
    def batch_get_repositories(
        self, context: RequestContext, repository_names: RepositoryNameList
    ) -> BatchGetRepositoriesOutput:
        raise NotImplementedError

    @handler("CreateApprovalRuleTemplate")
    def create_approval_rule_template(
        self,
        context: RequestContext,
        approval_rule_template_name: ApprovalRuleTemplateName,
        approval_rule_template_content: ApprovalRuleTemplateContent,
        approval_rule_template_description: ApprovalRuleTemplateDescription = None,
    ) -> CreateApprovalRuleTemplateOutput:
        raise NotImplementedError

    @handler("CreateBranch")
    def create_branch(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        branch_name: BranchName,
        commit_id: CommitId,
    ) -> None:
        raise NotImplementedError

    @handler("CreateCommit")
    def create_commit(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        branch_name: BranchName,
        parent_commit_id: CommitId = None,
        author_name: Name = None,
        email: Email = None,
        commit_message: Message = None,
        keep_empty_folders: KeepEmptyFolders = None,
        put_files: PutFileEntries = None,
        delete_files: DeleteFileEntries = None,
        set_file_modes: SetFileModeEntries = None,
    ) -> CreateCommitOutput:
        raise NotImplementedError

    @handler("CreatePullRequest")
    def create_pull_request(
        self,
        context: RequestContext,
        title: Title,
        targets: TargetList,
        description: Description = None,
        client_request_token: ClientRequestToken = None,
    ) -> CreatePullRequestOutput:
        raise NotImplementedError

    @handler("CreatePullRequestApprovalRule")
    def create_pull_request_approval_rule(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        approval_rule_name: ApprovalRuleName,
        approval_rule_content: ApprovalRuleContent,
    ) -> CreatePullRequestApprovalRuleOutput:
        raise NotImplementedError

    @handler("CreateRepository")
    def create_repository(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        repository_description: RepositoryDescription = None,
        tags: TagsMap = None,
    ) -> CreateRepositoryOutput:
        raise NotImplementedError

    @handler("CreateUnreferencedMergeCommit")
    def create_unreferenced_merge_commit(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        source_commit_specifier: CommitName,
        destination_commit_specifier: CommitName,
        merge_option: MergeOptionTypeEnum,
        conflict_detail_level: ConflictDetailLevelTypeEnum = None,
        conflict_resolution_strategy: ConflictResolutionStrategyTypeEnum = None,
        author_name: Name = None,
        email: Email = None,
        commit_message: Message = None,
        keep_empty_folders: KeepEmptyFolders = None,
        conflict_resolution: ConflictResolution = None,
    ) -> CreateUnreferencedMergeCommitOutput:
        raise NotImplementedError

    @handler("DeleteApprovalRuleTemplate")
    def delete_approval_rule_template(
        self, context: RequestContext, approval_rule_template_name: ApprovalRuleTemplateName
    ) -> DeleteApprovalRuleTemplateOutput:
        raise NotImplementedError

    @handler("DeleteBranch")
    def delete_branch(
        self, context: RequestContext, repository_name: RepositoryName, branch_name: BranchName
    ) -> DeleteBranchOutput:
        raise NotImplementedError

    @handler("DeleteCommentContent")
    def delete_comment_content(
        self, context: RequestContext, comment_id: CommentId
    ) -> DeleteCommentContentOutput:
        raise NotImplementedError

    @handler("DeleteFile")
    def delete_file(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        branch_name: BranchName,
        file_path: Path,
        parent_commit_id: CommitId,
        keep_empty_folders: KeepEmptyFolders = None,
        commit_message: Message = None,
        name: Name = None,
        email: Email = None,
    ) -> DeleteFileOutput:
        raise NotImplementedError

    @handler("DeletePullRequestApprovalRule")
    def delete_pull_request_approval_rule(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        approval_rule_name: ApprovalRuleName,
    ) -> DeletePullRequestApprovalRuleOutput:
        raise NotImplementedError

    @handler("DeleteRepository")
    def delete_repository(
        self, context: RequestContext, repository_name: RepositoryName
    ) -> DeleteRepositoryOutput:
        raise NotImplementedError

    @handler("DescribeMergeConflicts")
    def describe_merge_conflicts(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        destination_commit_specifier: CommitName,
        source_commit_specifier: CommitName,
        merge_option: MergeOptionTypeEnum,
        file_path: Path,
        max_merge_hunks: MaxResults = None,
        conflict_detail_level: ConflictDetailLevelTypeEnum = None,
        conflict_resolution_strategy: ConflictResolutionStrategyTypeEnum = None,
        next_token: NextToken = None,
    ) -> DescribeMergeConflictsOutput:
        raise NotImplementedError

    @handler("DescribePullRequestEvents")
    def describe_pull_request_events(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        pull_request_event_type: PullRequestEventType = None,
        actor_arn: Arn = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> DescribePullRequestEventsOutput:
        raise NotImplementedError

    @handler("DisassociateApprovalRuleTemplateFromRepository")
    def disassociate_approval_rule_template_from_repository(
        self,
        context: RequestContext,
        approval_rule_template_name: ApprovalRuleTemplateName,
        repository_name: RepositoryName,
    ) -> None:
        raise NotImplementedError

    @handler("EvaluatePullRequestApprovalRules")
    def evaluate_pull_request_approval_rules(
        self, context: RequestContext, pull_request_id: PullRequestId, revision_id: RevisionId
    ) -> EvaluatePullRequestApprovalRulesOutput:
        raise NotImplementedError

    @handler("GetApprovalRuleTemplate")
    def get_approval_rule_template(
        self, context: RequestContext, approval_rule_template_name: ApprovalRuleTemplateName
    ) -> GetApprovalRuleTemplateOutput:
        raise NotImplementedError

    @handler("GetBlob")
    def get_blob(
        self, context: RequestContext, repository_name: RepositoryName, blob_id: ObjectId
    ) -> GetBlobOutput:
        raise NotImplementedError

    @handler("GetBranch")
    def get_branch(
        self,
        context: RequestContext,
        repository_name: RepositoryName = None,
        branch_name: BranchName = None,
    ) -> GetBranchOutput:
        raise NotImplementedError

    @handler("GetComment")
    def get_comment(self, context: RequestContext, comment_id: CommentId) -> GetCommentOutput:
        raise NotImplementedError

    @handler("GetCommentReactions")
    def get_comment_reactions(
        self,
        context: RequestContext,
        comment_id: CommentId,
        reaction_user_arn: Arn = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> GetCommentReactionsOutput:
        raise NotImplementedError

    @handler("GetCommentsForComparedCommit")
    def get_comments_for_compared_commit(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        after_commit_id: CommitId,
        before_commit_id: CommitId = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> GetCommentsForComparedCommitOutput:
        raise NotImplementedError

    @handler("GetCommentsForPullRequest")
    def get_comments_for_pull_request(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        repository_name: RepositoryName = None,
        before_commit_id: CommitId = None,
        after_commit_id: CommitId = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> GetCommentsForPullRequestOutput:
        raise NotImplementedError

    @handler("GetCommit")
    def get_commit(
        self, context: RequestContext, repository_name: RepositoryName, commit_id: ObjectId
    ) -> GetCommitOutput:
        raise NotImplementedError

    @handler("GetDifferences")
    def get_differences(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        after_commit_specifier: CommitName,
        before_commit_specifier: CommitName = None,
        before_path: Path = None,
        after_path: Path = None,
        max_results: Limit = None,
        next_token: NextToken = None,
    ) -> GetDifferencesOutput:
        raise NotImplementedError

    @handler("GetFile")
    def get_file(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        file_path: Path,
        commit_specifier: CommitName = None,
    ) -> GetFileOutput:
        raise NotImplementedError

    @handler("GetFolder")
    def get_folder(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        folder_path: Path,
        commit_specifier: CommitName = None,
    ) -> GetFolderOutput:
        raise NotImplementedError

    @handler("GetMergeCommit")
    def get_merge_commit(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        source_commit_specifier: CommitName,
        destination_commit_specifier: CommitName,
        conflict_detail_level: ConflictDetailLevelTypeEnum = None,
        conflict_resolution_strategy: ConflictResolutionStrategyTypeEnum = None,
    ) -> GetMergeCommitOutput:
        raise NotImplementedError

    @handler("GetMergeConflicts")
    def get_merge_conflicts(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        destination_commit_specifier: CommitName,
        source_commit_specifier: CommitName,
        merge_option: MergeOptionTypeEnum,
        conflict_detail_level: ConflictDetailLevelTypeEnum = None,
        max_conflict_files: MaxResults = None,
        conflict_resolution_strategy: ConflictResolutionStrategyTypeEnum = None,
        next_token: NextToken = None,
    ) -> GetMergeConflictsOutput:
        raise NotImplementedError

    @handler("GetMergeOptions")
    def get_merge_options(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        source_commit_specifier: CommitName,
        destination_commit_specifier: CommitName,
        conflict_detail_level: ConflictDetailLevelTypeEnum = None,
        conflict_resolution_strategy: ConflictResolutionStrategyTypeEnum = None,
    ) -> GetMergeOptionsOutput:
        raise NotImplementedError

    @handler("GetPullRequest")
    def get_pull_request(
        self, context: RequestContext, pull_request_id: PullRequestId
    ) -> GetPullRequestOutput:
        raise NotImplementedError

    @handler("GetPullRequestApprovalStates")
    def get_pull_request_approval_states(
        self, context: RequestContext, pull_request_id: PullRequestId, revision_id: RevisionId
    ) -> GetPullRequestApprovalStatesOutput:
        raise NotImplementedError

    @handler("GetPullRequestOverrideState")
    def get_pull_request_override_state(
        self, context: RequestContext, pull_request_id: PullRequestId, revision_id: RevisionId
    ) -> GetPullRequestOverrideStateOutput:
        raise NotImplementedError

    @handler("GetRepository")
    def get_repository(
        self, context: RequestContext, repository_name: RepositoryName
    ) -> GetRepositoryOutput:
        raise NotImplementedError

    @handler("GetRepositoryTriggers")
    def get_repository_triggers(
        self, context: RequestContext, repository_name: RepositoryName
    ) -> GetRepositoryTriggersOutput:
        raise NotImplementedError

    @handler("ListApprovalRuleTemplates")
    def list_approval_rule_templates(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListApprovalRuleTemplatesOutput:
        raise NotImplementedError

    @handler("ListAssociatedApprovalRuleTemplatesForRepository")
    def list_associated_approval_rule_templates_for_repository(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListAssociatedApprovalRuleTemplatesForRepositoryOutput:
        raise NotImplementedError

    @handler("ListBranches")
    def list_branches(
        self, context: RequestContext, repository_name: RepositoryName, next_token: NextToken = None
    ) -> ListBranchesOutput:
        raise NotImplementedError

    @handler("ListPullRequests")
    def list_pull_requests(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        author_arn: Arn = None,
        pull_request_status: PullRequestStatusEnum = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListPullRequestsOutput:
        raise NotImplementedError

    @handler("ListRepositories")
    def list_repositories(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        sort_by: SortByEnum = None,
        order: OrderEnum = None,
    ) -> ListRepositoriesOutput:
        raise NotImplementedError

    @handler("ListRepositoriesForApprovalRuleTemplate")
    def list_repositories_for_approval_rule_template(
        self,
        context: RequestContext,
        approval_rule_template_name: ApprovalRuleTemplateName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListRepositoriesForApprovalRuleTemplateOutput:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: ResourceArn, next_token: NextToken = None
    ) -> ListTagsForResourceOutput:
        raise NotImplementedError

    @handler("MergeBranchesByFastForward")
    def merge_branches_by_fast_forward(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        source_commit_specifier: CommitName,
        destination_commit_specifier: CommitName,
        target_branch: BranchName = None,
    ) -> MergeBranchesByFastForwardOutput:
        raise NotImplementedError

    @handler("MergeBranchesBySquash")
    def merge_branches_by_squash(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        source_commit_specifier: CommitName,
        destination_commit_specifier: CommitName,
        target_branch: BranchName = None,
        conflict_detail_level: ConflictDetailLevelTypeEnum = None,
        conflict_resolution_strategy: ConflictResolutionStrategyTypeEnum = None,
        author_name: Name = None,
        email: Email = None,
        commit_message: Message = None,
        keep_empty_folders: KeepEmptyFolders = None,
        conflict_resolution: ConflictResolution = None,
    ) -> MergeBranchesBySquashOutput:
        raise NotImplementedError

    @handler("MergeBranchesByThreeWay")
    def merge_branches_by_three_way(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        source_commit_specifier: CommitName,
        destination_commit_specifier: CommitName,
        target_branch: BranchName = None,
        conflict_detail_level: ConflictDetailLevelTypeEnum = None,
        conflict_resolution_strategy: ConflictResolutionStrategyTypeEnum = None,
        author_name: Name = None,
        email: Email = None,
        commit_message: Message = None,
        keep_empty_folders: KeepEmptyFolders = None,
        conflict_resolution: ConflictResolution = None,
    ) -> MergeBranchesByThreeWayOutput:
        raise NotImplementedError

    @handler("MergePullRequestByFastForward")
    def merge_pull_request_by_fast_forward(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        repository_name: RepositoryName,
        source_commit_id: ObjectId = None,
    ) -> MergePullRequestByFastForwardOutput:
        raise NotImplementedError

    @handler("MergePullRequestBySquash")
    def merge_pull_request_by_squash(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        repository_name: RepositoryName,
        source_commit_id: ObjectId = None,
        conflict_detail_level: ConflictDetailLevelTypeEnum = None,
        conflict_resolution_strategy: ConflictResolutionStrategyTypeEnum = None,
        commit_message: Message = None,
        author_name: Name = None,
        email: Email = None,
        keep_empty_folders: KeepEmptyFolders = None,
        conflict_resolution: ConflictResolution = None,
    ) -> MergePullRequestBySquashOutput:
        raise NotImplementedError

    @handler("MergePullRequestByThreeWay")
    def merge_pull_request_by_three_way(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        repository_name: RepositoryName,
        source_commit_id: ObjectId = None,
        conflict_detail_level: ConflictDetailLevelTypeEnum = None,
        conflict_resolution_strategy: ConflictResolutionStrategyTypeEnum = None,
        commit_message: Message = None,
        author_name: Name = None,
        email: Email = None,
        keep_empty_folders: KeepEmptyFolders = None,
        conflict_resolution: ConflictResolution = None,
    ) -> MergePullRequestByThreeWayOutput:
        raise NotImplementedError

    @handler("OverridePullRequestApprovalRules")
    def override_pull_request_approval_rules(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        revision_id: RevisionId,
        override_status: OverrideStatus,
    ) -> None:
        raise NotImplementedError

    @handler("PostCommentForComparedCommit")
    def post_comment_for_compared_commit(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        after_commit_id: CommitId,
        content: Content,
        before_commit_id: CommitId = None,
        location: Location = None,
        client_request_token: ClientRequestToken = None,
    ) -> PostCommentForComparedCommitOutput:
        raise NotImplementedError

    @handler("PostCommentForPullRequest")
    def post_comment_for_pull_request(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        repository_name: RepositoryName,
        before_commit_id: CommitId,
        after_commit_id: CommitId,
        content: Content,
        location: Location = None,
        client_request_token: ClientRequestToken = None,
    ) -> PostCommentForPullRequestOutput:
        raise NotImplementedError

    @handler("PostCommentReply")
    def post_comment_reply(
        self,
        context: RequestContext,
        in_reply_to: CommentId,
        content: Content,
        client_request_token: ClientRequestToken = None,
    ) -> PostCommentReplyOutput:
        raise NotImplementedError

    @handler("PutCommentReaction")
    def put_comment_reaction(
        self, context: RequestContext, comment_id: CommentId, reaction_value: ReactionValue
    ) -> None:
        raise NotImplementedError

    @handler("PutFile")
    def put_file(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        branch_name: BranchName,
        file_content: FileContent,
        file_path: Path,
        file_mode: FileModeTypeEnum = None,
        parent_commit_id: CommitId = None,
        commit_message: Message = None,
        name: Name = None,
        email: Email = None,
    ) -> PutFileOutput:
        raise NotImplementedError

    @handler("PutRepositoryTriggers")
    def put_repository_triggers(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        triggers: RepositoryTriggersList,
    ) -> PutRepositoryTriggersOutput:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tags: TagsMap
    ) -> None:
        raise NotImplementedError

    @handler("TestRepositoryTriggers")
    def test_repository_triggers(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        triggers: RepositoryTriggersList,
    ) -> TestRepositoryTriggersOutput:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: ResourceArn, tag_keys: TagKeysList
    ) -> None:
        raise NotImplementedError

    @handler("UpdateApprovalRuleTemplateContent")
    def update_approval_rule_template_content(
        self,
        context: RequestContext,
        approval_rule_template_name: ApprovalRuleTemplateName,
        new_rule_content: ApprovalRuleTemplateContent,
        existing_rule_content_sha256: RuleContentSha256 = None,
    ) -> UpdateApprovalRuleTemplateContentOutput:
        raise NotImplementedError

    @handler("UpdateApprovalRuleTemplateDescription")
    def update_approval_rule_template_description(
        self,
        context: RequestContext,
        approval_rule_template_name: ApprovalRuleTemplateName,
        approval_rule_template_description: ApprovalRuleTemplateDescription,
    ) -> UpdateApprovalRuleTemplateDescriptionOutput:
        raise NotImplementedError

    @handler("UpdateApprovalRuleTemplateName")
    def update_approval_rule_template_name(
        self,
        context: RequestContext,
        old_approval_rule_template_name: ApprovalRuleTemplateName,
        new_approval_rule_template_name: ApprovalRuleTemplateName,
    ) -> UpdateApprovalRuleTemplateNameOutput:
        raise NotImplementedError

    @handler("UpdateComment")
    def update_comment(
        self, context: RequestContext, comment_id: CommentId, content: Content
    ) -> UpdateCommentOutput:
        raise NotImplementedError

    @handler("UpdateDefaultBranch")
    def update_default_branch(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        default_branch_name: BranchName,
    ) -> None:
        raise NotImplementedError

    @handler("UpdatePullRequestApprovalRuleContent")
    def update_pull_request_approval_rule_content(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        approval_rule_name: ApprovalRuleName,
        new_rule_content: ApprovalRuleContent,
        existing_rule_content_sha256: RuleContentSha256 = None,
    ) -> UpdatePullRequestApprovalRuleContentOutput:
        raise NotImplementedError

    @handler("UpdatePullRequestApprovalState")
    def update_pull_request_approval_state(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        revision_id: RevisionId,
        approval_state: ApprovalState,
    ) -> None:
        raise NotImplementedError

    @handler("UpdatePullRequestDescription")
    def update_pull_request_description(
        self, context: RequestContext, pull_request_id: PullRequestId, description: Description
    ) -> UpdatePullRequestDescriptionOutput:
        raise NotImplementedError

    @handler("UpdatePullRequestStatus")
    def update_pull_request_status(
        self,
        context: RequestContext,
        pull_request_id: PullRequestId,
        pull_request_status: PullRequestStatusEnum,
    ) -> UpdatePullRequestStatusOutput:
        raise NotImplementedError

    @handler("UpdatePullRequestTitle")
    def update_pull_request_title(
        self, context: RequestContext, pull_request_id: PullRequestId, title: Title
    ) -> UpdatePullRequestTitleOutput:
        raise NotImplementedError

    @handler("UpdateRepositoryDescription")
    def update_repository_description(
        self,
        context: RequestContext,
        repository_name: RepositoryName,
        repository_description: RepositoryDescription = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateRepositoryName")
    def update_repository_name(
        self, context: RequestContext, old_name: RepositoryName, new_name: RepositoryName
    ) -> None:
        raise NotImplementedError
