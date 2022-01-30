import sys
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ErrorCode = str
ErrorMessage = str
IonText = str
LedgerName = str
PageToken = str
SessionToken = str
Statement = str
TransactionId = str


class BadRequestException(ServiceException):
    Message: Optional[ErrorMessage]
    Code: Optional[ErrorCode]


class CapacityExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class InvalidSessionException(ServiceException):
    Message: Optional[ErrorMessage]
    Code: Optional[ErrorCode]


class LimitExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class OccConflictException(ServiceException):
    Message: Optional[ErrorMessage]


class RateExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class AbortTransactionRequest(TypedDict, total=False):
    pass


ProcessingTimeMilliseconds = int


class TimingInformation(TypedDict, total=False):
    ProcessingTimeMilliseconds: Optional[ProcessingTimeMilliseconds]


class AbortTransactionResult(TypedDict, total=False):
    TimingInformation: Optional[TimingInformation]


CommitDigest = bytes


class CommitTransactionRequest(TypedDict, total=False):
    TransactionId: TransactionId
    CommitDigest: CommitDigest


WriteIOs = int
ReadIOs = int


class IOUsage(TypedDict, total=False):
    ReadIOs: Optional[ReadIOs]
    WriteIOs: Optional[WriteIOs]


class CommitTransactionResult(TypedDict, total=False):
    TransactionId: Optional[TransactionId]
    CommitDigest: Optional[CommitDigest]
    TimingInformation: Optional[TimingInformation]
    ConsumedIOs: Optional[IOUsage]


class EndSessionRequest(TypedDict, total=False):
    pass


class EndSessionResult(TypedDict, total=False):
    TimingInformation: Optional[TimingInformation]


IonBinary = bytes


class ValueHolder(TypedDict, total=False):
    IonBinary: Optional[IonBinary]
    IonText: Optional[IonText]


StatementParameters = List[ValueHolder]


class ExecuteStatementRequest(TypedDict, total=False):
    TransactionId: TransactionId
    Statement: Statement
    Parameters: Optional[StatementParameters]


ValueHolders = List[ValueHolder]


class Page(TypedDict, total=False):
    Values: Optional[ValueHolders]
    NextPageToken: Optional[PageToken]


class ExecuteStatementResult(TypedDict, total=False):
    FirstPage: Optional[Page]
    TimingInformation: Optional[TimingInformation]
    ConsumedIOs: Optional[IOUsage]


class FetchPageRequest(TypedDict, total=False):
    TransactionId: TransactionId
    NextPageToken: PageToken


class FetchPageResult(TypedDict, total=False):
    Page: Optional[Page]
    TimingInformation: Optional[TimingInformation]
    ConsumedIOs: Optional[IOUsage]


class StartTransactionRequest(TypedDict, total=False):
    pass


class StartSessionRequest(TypedDict, total=False):
    LedgerName: LedgerName


class SendCommandRequest(ServiceRequest):
    SessionToken: Optional[SessionToken]
    StartSession: Optional[StartSessionRequest]
    StartTransaction: Optional[StartTransactionRequest]
    EndSession: Optional[EndSessionRequest]
    CommitTransaction: Optional[CommitTransactionRequest]
    AbortTransaction: Optional[AbortTransactionRequest]
    ExecuteStatement: Optional[ExecuteStatementRequest]
    FetchPage: Optional[FetchPageRequest]


class StartTransactionResult(TypedDict, total=False):
    TransactionId: Optional[TransactionId]
    TimingInformation: Optional[TimingInformation]


class StartSessionResult(TypedDict, total=False):
    SessionToken: Optional[SessionToken]
    TimingInformation: Optional[TimingInformation]


class SendCommandResult(TypedDict, total=False):
    StartSession: Optional[StartSessionResult]
    StartTransaction: Optional[StartTransactionResult]
    EndSession: Optional[EndSessionResult]
    CommitTransaction: Optional[CommitTransactionResult]
    AbortTransaction: Optional[AbortTransactionResult]
    ExecuteStatement: Optional[ExecuteStatementResult]
    FetchPage: Optional[FetchPageResult]


class QldbSessionApi:

    service = "qldb-session"
    version = "2019-07-11"

    @handler("SendCommand")
    def send_command(
        self,
        context: RequestContext,
        session_token: SessionToken = None,
        start_session: StartSessionRequest = None,
        start_transaction: StartTransactionRequest = None,
        end_session: EndSessionRequest = None,
        commit_transaction: CommitTransactionRequest = None,
        abort_transaction: AbortTransactionRequest = None,
        execute_statement: ExecuteStatementRequest = None,
        fetch_page: FetchPageRequest = None,
    ) -> SendCommandResult:
        raise NotImplementedError
