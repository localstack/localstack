import logging
import os
import re
import tempfile
from typing import Dict, List

from six import iteritems

from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_models import (
    DynamoDB,
    DynamoDBStream,
    ElasticSearch,
    EventSource,
    FirehoseStream,
    KinesisShard,
    KinesisStream,
    LambdaFunction,
    S3Bucket,
    S3Notification,
    SnsTopic,
    SqsQueue,
)
from localstack.utils.common import (
    clean_cache,
    download,
    load_file,
    md5,
    mkdir,
    mktime,
    parallelize,
    rm_rf,
    short_uid,
    unzip,
)

AWS_CACHE_TIMEOUT = 5  # 5 seconds
AWS_LAMBDA_CODE_CACHE_TIMEOUT = 5 * 60  # 5 minutes
MOCK_OBJ = False
TMP_DOWNLOAD_FILE_PATTERN = os.path.join(tempfile.gettempdir(), "tmpfile.*")
TMP_DOWNLOAD_CACHE_MAX_AGE = 30 * 60
last_cache_cleanup_time = {"time": 0}

# time delta for recent Kinesis events
KINESIS_RECENT_EVENTS_TIME_DIFF_SECS = 60

# logger
LOG = logging.getLogger(__name__)


def _connect(service, env=None, region=None):
    return aws_stack.connect_to_service(service, region_name=region)


def get_kinesis_streams(filter=".*", pool={}, env=None, region=None):
    if MOCK_OBJ:
        return []
    result = []
    try:
        kinesis_client = _connect("kinesis", region=region)
        out = kinesis_client.list_streams()
        for name in out["StreamNames"]:
            if re.match(filter, name):
                details = kinesis_client.describe_stream(StreamName=name)
                arn = details["StreamDescription"]["StreamARN"]
                stream = KinesisStream(arn)
                pool[arn] = stream
                stream.shards = get_kinesis_shards(stream_details=details, env=env, region=region)
                result.append(stream)
    except Exception:
        pass
    return result


def get_kinesis_shards(stream_name=None, stream_details=None, env=None, region=None):
    if not stream_details:
        kinesis_client = _connect("kinesis", env=env, region=region)
        stream_details = kinesis_client.describe_stream(StreamName=stream_name)
    shards = stream_details["StreamDescription"]["Shards"]
    result = []
    for s in shards:
        shard = KinesisShard(s["ShardId"])
        shard.start_key = s["HashKeyRange"]["StartingHashKey"]
        shard.end_key = s["HashKeyRange"]["EndingHashKey"]
        result.append(shard)
    return result


def get_sqs_queues(filter=".*", pool={}, env=None, region=None):
    result = []
    try:
        sqs_client = _connect("sqs", env=env, region=region)
        out = sqs_client.list_queues()
        queues = out["QueueUrls"]
        for q in queues:
            name = q.split("/")[-1]
            arn = aws_stack.sqs_queue_arn(name)
            if re.match(filter, name):
                queue = SqsQueue(arn)
                result.append(queue)
    except Exception:
        pass
    return result


def get_sns_topics(filter=".*", pool=None, env=None, region=None):
    result = []
    try:
        sns_client = _connect("sns", env=env, region=region)
        out = sns_client.list_topics()

        topics = out["Topics"]
        for t in topics:
            arn = t["TopicArn"]
            name = arn.split(":")[-1]
            if re.match(filter, name):
                obj = SnsTopic(arn)
                result.append(obj)

                if pool is not None:
                    pool[obj.id] = obj
    except Exception:
        pass
    return result


def get_lambda_functions(filter=".*", details=False, pool={}, env=None, region=None):
    if MOCK_OBJ:
        return []

    result = []

    def handle(func):
        func_name = func["FunctionName"]
        if re.match(filter, func_name):
            arn = func["FunctionArn"]
            f = LambdaFunction(arn)
            pool[arn] = f
            result.append(f)
            if details:
                sources = get_lambda_event_sources(f.name(), env=env)
                for src in sources:
                    arn = src["EventSourceArn"]
                    f.event_sources.append(EventSource.get(arn, pool=pool))
                try:
                    code_map = get_lambda_code(func_name, env=env)
                    f.targets = extract_endpoints(code_map, pool)
                except Exception:
                    LOG.warning("Unable to get code for lambda '%s'" % func_name)

    try:
        lambda_client = _connect("lambda", env=env, region=region)
        out = lambda_client.list_functions()
        parallelize(handle, out["Functions"])
    except Exception:
        pass
    return result


def get_lambda_event_sources(func_name=None, env=None, region=None):
    if MOCK_OBJ:
        return {}

    lambda_client = _connect("lambda", env=env, region=region)
    if func_name:
        out = lambda_client.list_event_source_mappings(FunctionName=func_name)
    else:
        out = lambda_client.list_event_source_mappings()
    result = out["EventSourceMappings"]
    return result


def get_lambda_code(func_name, retries=1, cache_time=None, env=None, region=None):
    if MOCK_OBJ:
        return ""
    env = aws_stack.get_environment(env)
    if cache_time is None and not aws_stack.is_local_env(env):
        cache_time = AWS_LAMBDA_CODE_CACHE_TIMEOUT
    lambda_client = _connect("lambda", env=env, region=region)
    out = lambda_client.get_function(FunctionName=func_name)
    loc = out["Code"]["Location"]
    hash = md5(loc)
    folder = TMP_DOWNLOAD_FILE_PATTERN.replace("*", hash)
    filename = "archive.zip"
    archive = "%s/%s" % (folder, filename)
    try:
        mkdir(folder)
        if not os.path.isfile(archive):
            download(loc, archive, verify_ssl=False)
        if len(os.listdir(folder)) <= 1:
            zip_path = os.path.join(folder, filename)
            unzip(zip_path, folder)
    except Exception as e:
        print("WARN: %s" % e)
        rm_rf(archive)
        if retries > 0:
            return get_lambda_code(func_name, retries=retries - 1, cache_time=1, env=env)
        else:
            print("WARNING: Unable to retrieve lambda code: %s" % e)

    # traverse subdirectories and get script sources
    result = {}
    for root, subdirs, files in os.walk(folder):
        for file in files:
            prefix = root.split(folder)[-1]
            key = "%s/%s" % (prefix, file)
            if re.match(r".+\.py$", key) or re.match(r".+\.js$", key):
                codefile = "%s/%s" % (root, file)
                result[key] = load_file(codefile)

    # cleanup cache
    clean_cache(
        file_pattern=TMP_DOWNLOAD_FILE_PATTERN,
        last_clean_time=last_cache_cleanup_time,
        max_age=TMP_DOWNLOAD_CACHE_MAX_AGE,
    )
    # TODO: delete only if cache_time is over
    rm_rf(folder)

    return result


def get_elasticsearch_domains(filter=".*", pool={}, env=None, region=None):
    result = []
    try:
        es_client = _connect("es", env=env, region=region)
        out = es_client.list_domain_names()

        def handle(domain):
            domain = domain["DomainName"]
            if re.match(filter, domain):
                details = es_client.describe_elasticsearch_domain(DomainName=domain)
                details = details["DomainStatus"]
                arn = details["ARN"]
                es = ElasticSearch(arn)
                es.endpoint = details.get("Endpoint", "n/a")
                result.append(es)
                pool[arn] = es

        parallelize(handle, out["DomainNames"])
    except Exception:
        pass

    return result


def get_dynamo_dbs(filter=".*", pool={}, env=None, region=None):
    result = []
    try:
        dynamodb_client = _connect("dynamodb", env=env, region=region)
        out = dynamodb_client.list_tables()

        def handle(table):
            if re.match(filter, table):
                details = dynamodb_client.describe_table(TableName=table)
                details = details["Table"]
                arn = details["TableArn"]
                db = DynamoDB(arn)
                db.count = details["ItemCount"]
                db.bytes = details["TableSizeBytes"]
                db.created_at = details["CreationDateTime"]
                result.append(db)
                pool[arn] = db

        parallelize(handle, out["TableNames"])
    except Exception:
        pass
    return result


def parse_notification_configuration(notification_config: Dict, pool=None) -> List[S3Notification]:
    # notification_config returned by:
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_notification_configuration
    notifications = list()

    arn_selectors = {
        "QueueConfigurations": "QueueArn",
        "TopicConfigurations": "TopicArn",
        "LambdaFunctionConfigurations": "LambdaFunctionArn",
    }

    for config_type, configs in notification_config.items():
        if config_type not in arn_selectors:
            continue

        for config in configs:
            try:
                arn = config[arn_selectors[config_type]]
                target = EventSource.get(arn, pool=pool)
                notification = S3Notification(target.id)
                notification.target = target
                notifications.append(notification)
            except Exception as e:
                LOG.warning("error parsing s3 notification: %s", e)

    return notifications


def get_s3_buckets(filter=".*", pool={}, details=False, env=None, region=None):
    result = []
    s3_client = _connect("s3", env=env, region=region)

    def handle(bucket):
        bucket_name = bucket["Name"]
        if re.match(filter, bucket_name):
            arn = "arn:aws:s3:::%s" % bucket_name
            bucket = S3Bucket(arn)
            result.append(bucket)
            pool[arn] = bucket
            if details:
                try:
                    response = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
                    if response:
                        notifications = parse_notification_configuration(response)
                        bucket.notifications.extend(notifications)

                except Exception as e:
                    LOG.warning("Unable to get details for bucket: %s", e)

    try:
        out = s3_client.list_buckets()
        # TODO: `handle` is not process safe, and threading may actually make the code slower
        parallelize(handle, out["Buckets"])
    except Exception:
        pass
    return result


def get_firehose_streams(filter=".*", pool={}, env=None, region=None):
    result = []
    try:
        firehose_client = _connect("firehose", env=env, region=region)
        out = firehose_client.list_delivery_streams()
        for stream_name in out["DeliveryStreamNames"]:
            if re.match(filter, stream_name):
                details = firehose_client.describe_delivery_stream(DeliveryStreamName=stream_name)
                details = details["DeliveryStreamDescription"]
                arn = details["DeliveryStreamARN"]
                s = FirehoseStream(arn)
                for dest in details["Destinations"]:
                    dest_s3 = dest["S3DestinationDescription"]["BucketARN"]
                    bucket = EventSource.get(dest_s3, pool=pool)
                    s.destinations.append(bucket)
                result.append(s)
    except Exception:
        pass
    return result


def read_kinesis_iterator(shard_iterator, max_results=10, env=None, region=None):
    kinesis_client = _connect("kinesis", env=env, region=region)
    result = kinesis_client.get_records(ShardIterator=shard_iterator, Limit=max_results)
    return result


def get_kinesis_events(stream_name, shard_id, max_results=10, env=None):
    records = []
    try:
        env = aws_stack.get_environment(env)
        records = aws_stack.kinesis_get_latest_records(
            stream_name, shard_id, count=max_results, env=env
        )
        for r in records:
            r["ApproximateArrivalTimestamp"] = mktime(r["ApproximateArrivalTimestamp"])
    except Exception:
        pass
    result = {"events": records}
    return result


def find_node_by_attribute(graph, key, value):
    for node in graph["nodes"]:
        if node[key] == value:
            return node
    return None


def find_node_by_id(graph, node_id):
    return find_node_by_attribute(graph, "id", node_id)


def find_edges_for_source(graph, node_id):
    return [edge for edge in graph["edges"] if edge["source"] == node_id]


def get_graph(name_filter=".*", env=None, **kwargs):
    result = {"nodes": [], "edges": []}

    pool = {}
    node_ids = {}
    region = kwargs.get("region")

    # Make sure we load components in the right order:
    # (ES,DynamoDB,S3) -> (Kinesis,Lambda)
    domains = get_elasticsearch_domains(name_filter, pool=pool, env=env, region=region)
    dbs = get_dynamo_dbs(name_filter, pool=pool, env=env, region=region)
    buckets = get_s3_buckets(name_filter, details=True, pool=pool, env=env, region=region)
    streams = get_kinesis_streams(name_filter, pool=pool, env=env, region=region)
    firehoses = get_firehose_streams(name_filter, pool=pool, env=env, region=region)
    lambdas = get_lambda_functions(name_filter, details=True, pool=pool, env=env, region=region)
    queues = get_sqs_queues(name_filter, pool=pool, env=env, region=region)
    topics = get_sns_topics(name_filter, pool=pool, env=env, region=region)

    for es in domains:
        uid = short_uid()
        node_ids[es.id] = uid
        result["nodes"].append({"id": uid, "arn": es.id, "name": es.name(), "type": "es"})
    for b in buckets:
        uid = short_uid()
        node_ids[b.id] = uid
        result["nodes"].append({"id": uid, "arn": b.id, "name": b.name(), "type": "s3"})
    for db in dbs:
        uid = short_uid()
        node_ids[db.id] = uid
        result["nodes"].append({"id": uid, "arn": db.id, "name": db.name(), "type": "dynamodb"})
    for s in streams:
        uid = short_uid()
        node_ids[s.id] = uid
        result["nodes"].append({"id": uid, "arn": s.id, "name": s.name(), "type": "kinesis"})
        for shard in s.shards:
            uid1 = short_uid()
            name = re.sub(r"shardId-0*", "", shard.id) or "0"
            result["nodes"].append(
                {
                    "id": uid1,
                    "arn": shard.id,
                    "name": name,
                    "type": "kinesis_shard",
                    "streamName": s.name(),
                    "parent": uid,
                }
            )
    for f in firehoses:
        uid = short_uid()
        node_ids[f.id] = uid
        result["nodes"].append({"id": uid, "arn": f.id, "name": f.name(), "type": "firehose"})
        for d in f.destinations:
            result["edges"].append({"source": uid, "target": node_ids[d.id]})
    for q in queues:
        uid = short_uid()
        node_ids[q.id] = uid
        result["nodes"].append({"id": uid, "arn": q.id, "name": q.name(), "type": "sqs"})
    for t in topics:
        uid = short_uid()
        node_ids[t.id] = uid
        result["nodes"].append({"id": uid, "arn": t.id, "name": t.name(), "type": "sns"})
    for lda in lambdas:
        uid = short_uid()
        node_ids[lda.id] = uid
        result["nodes"].append({"id": uid, "arn": lda.id, "name": lda.name(), "type": "lambda"})
        for s in lda.event_sources:
            lookup_id = s.id
            if isinstance(s, DynamoDBStream):
                lookup_id = s.table.id
            result["edges"].append({"source": node_ids.get(lookup_id), "target": uid})
        for t in lda.targets:
            lookup_id = t.id
            result["edges"].append({"source": uid, "target": node_ids.get(lookup_id)})
    for b in buckets:
        for n in b.notifications:
            src_uid = node_ids[b.id]
            tgt_uid = node_ids[n.target.id]
            result["edges"].append({"source": src_uid, "target": tgt_uid})

    return result


# TODO: Move to utils.common
def extract_endpoints(code_map, pool={}):
    result = []
    identifiers = []
    for key, code in iteritems(code_map):
        # Elasticsearch references
        pattern = r'[\'"](.*\.es\.amazonaws\.com)[\'"]'
        for es in re.findall(pattern, code):
            if es not in identifiers:
                identifiers.append(es)
                es = EventSource.get(es, pool=pool, type=ElasticSearch)
                if es:
                    result.append(es)
        # Elasticsearch references
        pattern = r"\.put_record_batch\([^,]+,\s*([^,\s]+)\s*,"
        for firehose in re.findall(pattern, code):
            if firehose not in identifiers:
                identifiers.append(firehose)
                firehose = EventSource.get(firehose, pool=pool, type=FirehoseStream)
                if firehose:
                    result.append(firehose)
        # DynamoDB references
        # TODO fix pattern to be generic
        pattern = r"\.(insert|get)_document\s*\([^,]+,\s*([^,\s]+)\s*,"
        for (op, dynamo) in re.findall(pattern, code):
            dynamo = resolve_string_or_variable(dynamo, code_map)
            if dynamo not in identifiers:
                identifiers.append(dynamo)
                dynamo = EventSource.get(dynamo, pool=pool, type=DynamoDB)
                if dynamo:
                    result.append(dynamo)
        # S3 references
        pattern = r"\.upload_file\([^,]+,\s*([^,\s]+)\s*,"
        for s3 in re.findall(pattern, code):
            s3 = resolve_string_or_variable(s3, code_map)
            if s3 not in identifiers:
                identifiers.append(s3)
                s3 = EventSource.get(s3, pool=pool, type=S3Bucket)
                if s3:
                    result.append(s3)
    return result


# TODO: Move to utils.common
def resolve_string_or_variable(string, code_map):
    if re.match(r'^["\'].*["\']$', string):
        return string.replace('"', "").replace("'", "")
    LOG.warning("Variable resolution not implemented")
    return None
