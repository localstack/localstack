import os

# event type constants
EVENT_START_INFRA = "inf.up"
EVENT_STOP_INFRA = "inf.dn"
EVENT_KINESIS_CREATE_STREAM = "kns.cs"
EVENT_KINESIS_DELETE_STREAM = "kns.ds"
EVENT_LAMBDA_CREATE_FUNC = "lmb.cf"
EVENT_LAMBDA_DELETE_FUNC = "lmb.df"
EVENT_LAMBDA_INVOKE_FUNC = "lmb.if"
EVENT_SQS_CREATE_QUEUE = "sqs.cq"
EVENT_SQS_DELETE_QUEUE = "sqs.dq"
EVENT_SNS_CREATE_TOPIC = "sns.ct"
EVENT_SNS_DELETE_TOPIC = "sns.dt"
EVENT_S3_CREATE_BUCKET = "s3.cb"
EVENT_S3_DELETE_BUCKET = "s3.db"
EVENT_STEPFUNCTIONS_CREATE_SM = "stf.cm"
EVENT_STEPFUNCTIONS_DELETE_SM = "stf.dm"
EVENT_APIGW_CREATE_API = "agw.ca"
EVENT_APIGW_DELETE_API = "agw.da"
EVENT_DYNAMODB_CREATE_TABLE = "ddb.ct"
EVENT_DYNAMODB_DELETE_TABLE = "ddb.dt"
EVENT_DYNAMODB_CREATE_STREAM = "ddb.cs"
EVENT_CLOUDFORMATION_CREATE_STACK = "clf.cs"
EVENT_ES_CREATE_DOMAIN = "es.cd"
EVENT_ES_DELETE_DOMAIN = "es.dd"
EVENT_OPENSEARCH_CREATE_DOMAIN = "os.cd"
EVENT_OPENSEARCH_DELETE_DOMAIN = "os.dd"
EVENT_FIREHOSE_CREATE_STREAM = "fho.cs"
EVENT_FIREHOSE_DELETE_STREAM = "fho.ds"


def is_travis():
    return os.environ.get("TRAVIS", "").lower() in ["true", "1"]


def get_hash(name):
    if not name:
        return "0"
    max_hash = 10000000000
    hashed = hash(name) % max_hash
    hashed = hex(hashed).replace("0x", "")
    return hashed


def fire_event(event_type, payload=None):
    # TODO: remove legacy analytics from code
    pass
