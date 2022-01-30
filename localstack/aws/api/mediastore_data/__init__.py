import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ContentRangePattern = str
ContentType = str
ETag = str
ErrorMessage = str
ItemName = str
ListLimit = int
ListPathNaming = str
PaginationToken = str
PathNaming = str
RangePattern = str
SHA256Hash = str
StringPrimitive = str
statusCode = int


class ItemType(str):
    OBJECT = "OBJECT"
    FOLDER = "FOLDER"


class StorageClass(str):
    TEMPORAL = "TEMPORAL"


class UploadAvailability(str):
    STANDARD = "STANDARD"
    STREAMING = "STREAMING"


class ContainerNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]


class InternalServerError(ServiceException):
    Message: Optional[ErrorMessage]


class ObjectNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]


class RequestedRangeNotSatisfiableException(ServiceException):
    Message: Optional[ErrorMessage]


class DeleteObjectRequest(ServiceRequest):
    Path: PathNaming


class DeleteObjectResponse(TypedDict, total=False):
    pass


class DescribeObjectRequest(ServiceRequest):
    Path: PathNaming


TimeStamp = datetime
NonNegativeLong = int


class DescribeObjectResponse(TypedDict, total=False):
    ETag: Optional[ETag]
    ContentType: Optional[ContentType]
    ContentLength: Optional[NonNegativeLong]
    CacheControl: Optional[StringPrimitive]
    LastModified: Optional[TimeStamp]


class GetObjectRequest(ServiceRequest):
    Path: PathNaming
    Range: Optional[RangePattern]


PayloadBlob = bytes


class GetObjectResponse(TypedDict, total=False):
    Body: Optional[PayloadBlob]
    CacheControl: Optional[StringPrimitive]
    ContentRange: Optional[ContentRangePattern]
    ContentLength: Optional[NonNegativeLong]
    ContentType: Optional[ContentType]
    ETag: Optional[ETag]
    LastModified: Optional[TimeStamp]
    StatusCode: statusCode


class Item(TypedDict, total=False):
    Name: Optional[ItemName]
    Type: Optional[ItemType]
    ETag: Optional[ETag]
    LastModified: Optional[TimeStamp]
    ContentType: Optional[ContentType]
    ContentLength: Optional[NonNegativeLong]


ItemList = List[Item]


class ListItemsRequest(ServiceRequest):
    Path: Optional[ListPathNaming]
    MaxResults: Optional[ListLimit]
    NextToken: Optional[PaginationToken]


class ListItemsResponse(TypedDict, total=False):
    Items: Optional[ItemList]
    NextToken: Optional[PaginationToken]


class PutObjectRequest(ServiceRequest):
    Body: PayloadBlob
    Path: PathNaming
    ContentType: Optional[ContentType]
    CacheControl: Optional[StringPrimitive]
    StorageClass: Optional[StorageClass]
    UploadAvailability: Optional[UploadAvailability]


class PutObjectResponse(TypedDict, total=False):
    ContentSHA256: Optional[SHA256Hash]
    ETag: Optional[ETag]
    StorageClass: Optional[StorageClass]


class MediastoreDataApi:

    service = "mediastore-data"
    version = "2017-09-01"

    @handler("DeleteObject")
    def delete_object(self, context: RequestContext, path: PathNaming) -> DeleteObjectResponse:
        raise NotImplementedError

    @handler("DescribeObject")
    def describe_object(self, context: RequestContext, path: PathNaming) -> DescribeObjectResponse:
        raise NotImplementedError

    @handler("GetObject")
    def get_object(
        self, context: RequestContext, path: PathNaming, range: RangePattern = None
    ) -> GetObjectResponse:
        raise NotImplementedError

    @handler("ListItems")
    def list_items(
        self,
        context: RequestContext,
        path: ListPathNaming = None,
        max_results: ListLimit = None,
        next_token: PaginationToken = None,
    ) -> ListItemsResponse:
        raise NotImplementedError

    @handler("PutObject")
    def put_object(
        self,
        context: RequestContext,
        body: PayloadBlob,
        path: PathNaming,
        content_type: ContentType = None,
        cache_control: StringPrimitive = None,
        storage_class: StorageClass = None,
        upload_availability: UploadAvailability = None,
    ) -> PutObjectResponse:
        raise NotImplementedError
