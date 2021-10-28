import json
import logging
import time
from datetime import datetime

import six

from localstack.utils.common import timestamp_millis

if six.PY3:
    long = int

LOG = logging.getLogger(__name__)


class Component(object):
    def __init__(self, id, env=None):
        self.id = id
        self.env = env
        self.created_at = None

    def name(self):
        return self.id

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "<%s:%s>" % (self.__class__.__name__, self.id)


class KinesisStream(Component):
    def __init__(self, id, params=None, num_shards=1, connection=None):
        super(KinesisStream, self).__init__(id)
        params = params or {}
        self.shards = []
        self.stream_name = params.get("name", self.name())
        self.num_shards = params.get("shards", num_shards)
        self.conn = connection
        self.stream_info = params

    def name(self):
        return self.id.split(":stream/")[-1]

    def connect(self, connection):
        self.conn = connection

    def describe(self):
        r = self.conn.describe_stream(StreamName=self.stream_name)
        return r.get("StreamDescription")

    def create(self, raise_on_error=False):
        try:
            self.conn.create_stream(StreamName=self.stream_name, ShardCount=self.num_shards)
        except Exception as e:
            # TODO catch stream already exists exception, otherwise rethrow
            if raise_on_error:
                raise e

    def get_status(self):
        description = self.describe()
        return description.get("StreamStatus")

    def put(self, data, key):
        if not isinstance(data, str):
            data = json.dumps(data)
        return self.conn.put_record(StreamName=self.stream_name, Data=data, PartitionKey=key)

    def read(self, amount=-1, shard="shardId-000000000001"):
        if not self.conn:
            raise Exception("Please create the Kinesis connection first.")
        s_iterator = self.conn.get_shard_iterator(self.stream_name, shard, "TRIM_HORIZON")
        record = self.conn.get_records(s_iterator["ShardIterator"])
        while True:
            try:
                if record["NextShardIterator"] is None:
                    break
                else:
                    next_entry = self.conn.get_records(record["NextShardIterator"])
                    if len(next_entry["Records"]):
                        print(next_entry["Records"][0]["Data"])
                    record = next_entry
            except Exception as e:
                print('Error reading from Kinesis stream "%s": %s' % (self.stream_name, e))

    def wait_for(self):
        GET_STATUS_SLEEP_SECS = 5
        GET_STATUS_RETRIES = 50
        for i in range(0, GET_STATUS_RETRIES):
            try:
                status = self.get_status()
                if status == "ACTIVE":
                    return
            except Exception:
                # swallowing this exception should be ok, as we are in a retry loop
                pass
            time.sleep(GET_STATUS_SLEEP_SECS)
        raise Exception('Failed to get active status for stream "%s", giving up' % self.stream_name)

    def destroy(self):
        self.conn.delete_stream(StreamName=self.stream_name)
        time.sleep(2)


class KinesisShard(Component):
    MAX_KEY = "340282366920938463463374607431768211455"

    def __init__(self, id):
        super(KinesisShard, self).__init__(id)
        self.stream = None
        self.start_key = "0"
        self.end_key = KinesisShard.MAX_KEY  # 128 times '1' binary as decimal
        self.child_shards = []

    def print_tree(self, indent=""):
        print("%s%s" % (indent, self))
        for c in self.child_shards:
            c.print_tree(indent=indent + "   ")

    def length(self):
        return long(self.end_key) - long(self.start_key)

    def percent(self):
        return 100.0 * self.length() / float(KinesisShard.MAX_KEY)

    def __str__(self):
        return "Shard(%s, length=%s, percent=%s, start=%s, end=%s)" % (
            self.id,
            self.length(),
            self.percent(),
            self.start_key,
            self.end_key,
        )

    @staticmethod
    def sort(shards):
        def compare(x, y):
            s1 = long(x.start_key)
            s2 = long(y.start_key)
            if s1 < s2:
                return -1
            elif s1 > s2:
                return 1
            else:
                return 0

        return sorted(shards, cmp=compare)

    @staticmethod
    def max(shards):
        max_shard = None
        max_length = long(0)
        for s in shards:
            if s.length() > max_length:
                max_shard = s
                max_length = s.length()
        return max_shard


class FirehoseStream(KinesisStream):
    def __init__(self, id):
        super(FirehoseStream, self).__init__(id)
        self.destinations = []

    def name(self):
        return self.id.split(":deliverystream/")[-1]


class CodeSigningConfig:
    def __init__(self, arn, id, signing_profile_version_arns):
        self.arn = arn
        self.id = id
        self.signing_profile_version_arns = signing_profile_version_arns
        self.description = ""
        self.untrusted_artifact_on_deployment = "Warn"
        self.last_modified = None


class LambdaFunction(Component):
    def __init__(self, arn):
        super(LambdaFunction, self).__init__(arn)
        self.event_sources = []
        self.targets = []
        self.versions = {}
        self.aliases = {}
        self.envvars = {}
        self.tags = {}
        self.concurrency = None
        self.runtime = None
        self.handler = None
        self.cwd = None
        self.timeout = None
        self.last_modified = None
        self.vpc_config = None
        self.role = None
        self.kms_key_arn = None
        self.memory_size = None
        self.code = None
        self.dead_letter_config = None
        self.on_successful_invocation = None
        self.on_failed_invocation = None
        self.max_retry_attempts = None
        self.max_event_age = None
        self.description = ""
        self.code_signing_config_arn = None
        self.package_type = None
        self.image_config = {}
        self.tracing_config = {}

    def set_dead_letter_config(self, data):
        config = data.get("DeadLetterConfig")
        if not config:
            return
        self.dead_letter_config = config
        target_arn = config.get("TargetArn") or ""
        if ":sqs:" not in target_arn and ":sns:" not in target_arn:
            raise Exception(
                'Dead letter queue ARN "%s" requires a valid SQS queue or SNS topic' % target_arn
            )

    def get_function_event_invoke_config(self):
        response = {}

        if self.max_retry_attempts is not None:
            response.update({"MaximumRetryAttempts": self.max_retry_attempts})

        if self.max_event_age is not None:
            response.update({"MaximumEventAgeInSeconds": self.max_event_age})

        if self.on_successful_invocation or self.on_failed_invocation:
            response.update({"DestinationConfig": {}})
            if self.on_successful_invocation:
                response["DestinationConfig"].update(
                    {"OnSuccess": {"Destination": self.on_successful_invocation}}
                )
            if self.on_failed_invocation:
                response["DestinationConfig"].update(
                    {"OnFailure": {"Destination": self.on_failed_invocation}}
                )
        if not response:
            return None
        response.update(
            {
                "LastModified": timestamp_millis(self.last_modified),
                "FunctionArn": str(self.id),
            }
        )
        return response

    def clear_function_event_invoke_config(self):
        if hasattr(self, "dead_letter_config"):
            self.dead_letter_config = None
        if hasattr(self, "on_successful_invocation"):
            self.on_successful_invocation = None
        if hasattr(self, "on_failed_invocation"):
            self.on_failed_invocation = None
        if hasattr(self, "max_retry_attempts"):
            self.max_retry_attempts = None
        if hasattr(self, "max_event_age"):
            self.max_event_age = None

    def put_function_event_invoke_config(self, data):
        if not isinstance(data, dict):
            return

        updated = False
        if "DestinationConfig" in data:
            if "OnFailure" in data["DestinationConfig"]:
                dlq_arn = data["DestinationConfig"]["OnFailure"]["Destination"]
                self.on_failed_invocation = dlq_arn
                updated = True

            if "OnSuccess" in data["DestinationConfig"]:
                sq_arn = data["DestinationConfig"]["OnSuccess"]["Destination"]
                self.on_successful_invocation = sq_arn
                updated = True

        if "MaximumRetryAttempts" in data:
            try:
                max_retry_attempts = int(data["MaximumRetryAttempts"])
            except Exception:
                max_retry_attempts = 3

            self.max_retry_attempts = max_retry_attempts
            updated = True

        if "MaximumEventAgeInSeconds" in data:
            try:
                max_event_age = int(data["MaximumEventAgeInSeconds"])
            except Exception:
                max_event_age = 3600

            self.max_event_age = max_event_age
            updated = True

        if updated:
            self.last_modified = datetime.utcnow()

        return self

    def destination_enabled(self):
        return self.on_successful_invocation is not None or self.on_failed_invocation is not None

    def get_version(self, version):
        return self.versions.get(version)

    def max_version(self):
        versions = [int(key) for key in self.versions.keys() if key != "$LATEST"]
        return versions and max(versions) or 0

    def name(self):
        # Example ARN: arn:aws:lambda:aws-region:acct-id:function:helloworld:1
        return self.id.split(":")[6]

    def region(self):
        return self.id.split(":")[3]

    def arn(self):
        return self.id

    def function(self, qualifier: str = None):
        return self.versions.get(self.get_qualifier_version(qualifier)).get("Function")

    def get_qualifier_version(self, qualifier: str = None) -> str:
        if not qualifier:
            qualifier = "$LATEST"
        return (
            qualifier
            if qualifier in self.versions
            else self.aliases.get(qualifier).get("FunctionVersion")
        )

    def qualifier_exists(self, qualifier):
        return qualifier in self.aliases or qualifier in self.versions

    def __str__(self):
        return "<%s:%s>" % (self.__class__.__name__, self.name())


class DynamoDB(Component):
    def __init__(self, id, env=None):
        super(DynamoDB, self).__init__(id, env=env)
        self.count = -1
        self.bytes = -1

    def name(self):
        return self.id.split(":table/")[-1]


class DynamoDBStream(Component):
    def __init__(self, id):
        super(DynamoDBStream, self).__init__(id)
        self.table = None


class DynamoDBItem(Component):
    def __init__(self, id, table=None, keys=None):
        super(DynamoDBItem, self).__init__(id)
        self.table = table
        self.keys = keys

    def __eq__(self, other):
        if not isinstance(other, DynamoDBItem):
            return False
        return other.table == self.table and other.id == self.id and other.keys == self.keys

    def __hash__(self):
        return hash(self.table) + hash(self.id) + hash(self.keys)


class ElasticSearch(Component):
    def __init__(self, id):
        super(ElasticSearch, self).__init__(id)
        self.indexes = []
        self.endpoint = None

    def name(self):
        return self.id.split(":domain/")[-1]


class SqsQueue(Component):
    def __init__(self, id):
        super(SqsQueue, self).__init__(id)

    def name(self):
        return self.id.split(":")[-1]


class SnsTopic(Component):
    def __init__(self, id):
        super(SnsTopic, self).__init__(id)

    def name(self):
        return self.id.split(":")[-1]


class S3Bucket(Component):
    def __init__(self, id):
        super(S3Bucket, self).__init__(id)
        self.notifications = []

    def name(self):
        return self.id.split("arn:aws:s3:::")[-1]


class S3Notification(Component):
    def __init__(self, id):
        super(S3Notification, self).__init__(id)
        self.target = None
        self.trigger = None


class EventSource(Component):
    def __init__(self, id):
        super(EventSource, self).__init__(id)

    @staticmethod
    def get(obj, pool=None, type=None):
        pool = pool or {}
        if not obj:
            return None
        if isinstance(obj, Component):
            obj = obj.id
        if obj in pool:
            return pool[obj]
        inst = None
        if obj.startswith("arn:aws:kinesis:"):
            inst = KinesisStream(obj)
        elif obj.startswith("arn:aws:lambda:"):
            inst = LambdaFunction(obj)
        elif obj.startswith("arn:aws:dynamodb:"):
            if "/stream/" in obj:
                table_id = obj.split("/stream/")[0]
                table = DynamoDB(table_id)
                inst = DynamoDBStream(obj)
                inst.table = table
            else:
                inst = DynamoDB(obj)
        elif obj.startswith("arn:aws:sqs:"):
            inst = SqsQueue(obj)
        elif obj.startswith("arn:aws:sns:"):
            inst = SnsTopic(obj)
        elif type:
            for o in EventSource.filter_type(pool, type):
                if o.name() == obj:
                    return o
                if type == ElasticSearch:
                    if o.endpoint == obj:
                        return o
        else:
            print("Unexpected object name: '%s'" % obj)
        return inst

    @staticmethod
    def filter_type(pool, type):
        return [obj for obj in six.itervalues(pool) if isinstance(obj, type)]
