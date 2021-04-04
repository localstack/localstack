import re
import os
import json
import boto3
import socket
import logging
import tempfile
from six import iteritems
from localstack.config import DEFAULT_REGION
from localstack.utils.aws import aws_stack
from localstack.utils.common import (short_uid, parallelize, is_port_open,
    to_str, rm_rf, unzip, download, clean_cache, mktime, load_file, mkdir, md5)
from localstack.utils.bootstrap import is_api_enabled
from localstack.utils.aws.aws_models import (ElasticSearch, S3Notification,
    EventSource, DynamoDB, DynamoDBStream, FirehoseStream, S3Bucket, SqsQueue,
    KinesisShard, KinesisStream, LambdaFunction)

AWS_CACHE_TIMEOUT = 5  # 5 seconds
AWS_LAMBDA_CODE_CACHE_TIMEOUT = 5 * 60  # 5 minutes
MOCK_OBJ = False
TMP_DOWNLOAD_FILE_PATTERN = os.path.join(tempfile.gettempdir(), 'tmpfile.*')
TMP_DOWNLOAD_CACHE_MAX_AGE = 30 * 60
last_cache_cleanup_time = {'time': 0}

# time delta for recent Kinesis events
KINESIS_RECENT_EVENTS_TIME_DIFF_SECS = 60

# logger
LOG = logging.getLogger(__name__)


def run_cached(cmd, cmd_params, cache_duration_secs=None):
    if cache_duration_secs is None:
        cache_duration_secs = AWS_CACHE_TIMEOUT
    env_vars = os.environ.copy()
    env_vars.update({
        'AWS_ACCESS_KEY_ID': os.environ.get('AWS_ACCESS_KEY_ID') or 'test',
        'AWS_SECRET_ACCESS_KEY': os.environ.get('AWS_SECRET_ACCESS_KEY') or 'test',
        'AWS_DEFAULT_REGION': DEFAULT_REGION or os.environ.get('AWS_DEFAULT_REGION'),
        'PYTHONWARNINGS': 'ignore:Unverified HTTPS request'
    })
    error = None
    try:
        return cmd.__call__(cmd_params)
    except Exception as e:
        error = e
    if error:
        LOG.warning('Error running command: %s %s' % (cmd, error))
        raise error


def run_aws_cmd(service, cmd_method, cmd_params=None, env=None, cache_duration_secs=None):
    client = aws_client(service, env)
    method = getattr(client, cmd_method)

    cmd = method
    if not is_api_enabled(service):
        return '{}'
    return run_cached(cmd, cmd_params, cache_duration_secs=cache_duration_secs)


def cmd_s3api(cmd_method, cmd_params=None, env=None):
    return run_aws_cmd('s3api', cmd_method, cmd_params, env=env)


def cmd_es(cmd_method, cmd_params=None, env=None):
    return run_aws_cmd('es', cmd_method, cmd_params, env=env)


def cmd_kinesis(cmd_method, cmd_params=None, env=None, cache_duration_secs=None):
    return run_aws_cmd('kinesis', cmd_method, cmd_params, env,
        cache_duration_secs=cache_duration_secs)


def cmd_dynamodb(cmd_method, cmd_params=None, env=None):
    return run_aws_cmd('dynamodb', cmd_method, cmd_params, env=env)


def cmd_firehose(cmd_method, cmd_params=None, env=None):
    return run_aws_cmd('firehose', cmd_method, cmd_params, env=env)


def cmd_sqs(cmd_method, cmd_params=None, env=None):
    return run_aws_cmd('sqs', cmd_method, cmd_params, env=env)


def cmd_lambda(cmd_method, cmd_params=None, env=None, cache_duration_secs=None):
    return run_aws_cmd('lambda', cmd_method, cmd_params, env,
        cache_duration_secs=cache_duration_secs)


def aws_client(service, env):
    use_ssl = False
    verify_ssl = False
    endpoint_url = None
    env = aws_stack.get_environment(env)
    if aws_stack.is_local_env(env):
        endpoint_url = aws_stack.get_local_service_url(service)
    if endpoint_url:
        if not is_port_open(endpoint_url):
            raise socket.error()
        if endpoint_url.startswith('https://'):
            use_ssl = True
    client = boto3.client(service_name=service, use_ssl=use_ssl, verify=verify_ssl, endpoint_url=endpoint_url)
    return client


def get_kinesis_streams(filter='.*', pool={}, env=None):
    if MOCK_OBJ:
        return []
    result = []
    try:
        out = cmd_kinesis('list_streams', env=env)
        out = json.loads(out)
        for name in out['StreamNames']:
            if re.match(filter, name):
                details = cmd_kinesis('describe_stream', 'StreamArn=%s, Limit=1000' % name, env=env)
                details = json.loads(details)
                arn = details['StreamDescription']['StreamARN']
                stream = KinesisStream(arn)
                pool[arn] = stream
                stream.shards = get_kinesis_shards(stream_details=details, env=env)
                result.append(stream)
    except Exception:
        pass
    return result


def get_kinesis_shards(stream_name=None, stream_details=None, env=None):
    if not stream_details:
        out = cmd_kinesis('describe_stream', 'StreamArn=%s, Limit=1000' % stream_name, env=env)
        stream_details = json.loads(out)
    shards = stream_details['StreamDescription']['Shards']
    result = []
    for s in shards:
        shard = KinesisShard(s['ShardId'])
        shard.start_key = s['HashKeyRange']['StartingHashKey']
        shard.end_key = s['HashKeyRange']['EndingHashKey']
        result.append(shard)
    return result


def get_sqs_queues(filter='.*', pool={}, env=None):
    result = []
    try:
        out = cmd_sqs('list_queues', env=env)
        if not out.strip():
            return result
        queues = json.loads(out)['QueueUrls']
        for q in queues:
            name = q.split('/')[-1]
            arn = aws_stack.sqs_queue_arn(name)
            if re.match(filter, name):
                queue = SqsQueue(arn)
                result.append(queue)
    except Exception:
        pass
    return result


# TODO move to util
def resolve_string_or_variable(string, code_map):
    if re.match(r'^["\'].*["\']$', string):
        return string.replace('"', '').replace("'", '')
    LOG.warning('Variable resolution not implemented')
    return None


# TODO move to util
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
        pattern = r'\.put_record_batch\([^,]+,\s*([^,\s]+)\s*,'
        for firehose in re.findall(pattern, code):
            if firehose not in identifiers:
                identifiers.append(firehose)
                firehose = EventSource.get(firehose, pool=pool, type=FirehoseStream)
                if firehose:
                    result.append(firehose)
        # DynamoDB references
        # TODO fix pattern to be generic
        pattern = r'\.(insert|get)_document\s*\([^,]+,\s*([^,\s]+)\s*,'
        for (op, dynamo) in re.findall(pattern, code):
            dynamo = resolve_string_or_variable(dynamo, code_map)
            if dynamo not in identifiers:
                identifiers.append(dynamo)
                dynamo = EventSource.get(dynamo, pool=pool, type=DynamoDB)
                if dynamo:
                    result.append(dynamo)
        # S3 references
        pattern = r'\.upload_file\([^,]+,\s*([^,\s]+)\s*,'
        for s3 in re.findall(pattern, code):
            s3 = resolve_string_or_variable(s3, code_map)
            if s3 not in identifiers:
                identifiers.append(s3)
                s3 = EventSource.get(s3, pool=pool, type=S3Bucket)
                if s3:
                    result.append(s3)
    return result


def get_lambda_functions(filter='.*', details=False, pool={}, env=None):
    if MOCK_OBJ:
        return []

    result = []

    def handle(func):
        func_name = func['FunctionName']
        if re.match(filter, func_name):
            arn = func['FunctionArn']
            f = LambdaFunction(arn)
            pool[arn] = f
            result.append(f)
            if details:
                sources = get_lambda_event_sources(f.name(), env=env)
                for src in sources:
                    arn = src['EventSourceArn']
                    f.event_sources.append(EventSource.get(arn, pool=pool))
                try:
                    code_map = get_lambda_code(func_name, env=env)
                    f.targets = extract_endpoints(code_map, pool)
                except Exception:
                    LOG.warning("Unable to get code for lambda '%s'" % func_name)

    try:
        out = cmd_lambda('list_functions', env=env)
        out = json.loads(out)
        parallelize(handle, out['Functions'])
    except Exception:
        pass
    return result


def get_lambda_event_sources(func_name=None, env=None):
    if MOCK_OBJ:
        return {}

    cmd = 'list_event_source_mappings'
    if func_name:
        out = cmd_lambda(cmd, 'FunctionName=%s' % func_name, env=env)
    else:
        out = cmd_lambda(cmd, env=env)
    out = json.loads(out)
    result = out['EventSourceMappings']
    return result


def get_lambda_code(func_name, retries=1, cache_time=None, env=None):
    if MOCK_OBJ:
        return ''
    env = aws_stack.get_environment(env)
    if cache_time is None and not aws_stack.is_local_env(env):
        cache_time = AWS_LAMBDA_CODE_CACHE_TIMEOUT
    out = cmd_lambda('get_function', 'FunctionName=%s' % func_name, env=env, cache_duration_secs=cache_time)
    out = json.loads(out)
    loc = out['Code']['Location']
    hash = md5(loc)
    folder = TMP_DOWNLOAD_FILE_PATTERN.replace('*', hash)
    filename = 'archive.zip'
    archive = '%s/%s' % (folder, filename)
    try:
        mkdir(folder)
        if not os.path.isfile(archive):
            download(loc, archive, verify_ssl=False)
        if len(os.listdir(folder)) <= 1:
            zip_path = os.path.join(folder, filename)
            unzip(zip_path, folder)
    except Exception as e:
        print('WARN: %s' % e)
        rm_rf(archive)
        if retries > 0:
            return get_lambda_code(func_name, retries=retries - 1, cache_time=1, env=env)
        else:
            print('WARNING: Unable to retrieve lambda code: %s' % e)

    # traverse subdirectories and get script sources
    result = {}
    for root, subdirs, files in os.walk(folder):
        for file in files:
            prefix = root.split(folder)[-1]
            key = '%s/%s' % (prefix, file)
            if re.match(r'.+\.py$', key) or re.match(r'.+\.js$', key):
                codefile = '%s/%s' % (root, file)
                result[key] = load_file(codefile)

    # cleanup cache
    clean_cache(file_pattern=TMP_DOWNLOAD_FILE_PATTERN,
        last_clean_time=last_cache_cleanup_time,
        max_age=TMP_DOWNLOAD_CACHE_MAX_AGE)
    # TODO: delete only if cache_time is over
    rm_rf(folder)

    return result


def get_elasticsearch_domains(filter='.*', pool={}, env=None):
    result = []
    try:
        out = cmd_es('list_domain_names', env)
        out = json.loads(out)

        def handle(domain):
            domain = domain['DomainName']
            if re.match(filter, domain):
                details = cmd_es('describe_elasticsearch_domain', 'DomainName=%s' % domain, env=env)
                details = json.loads(details)['DomainStatus']
                arn = details['ARN']
                es = ElasticSearch(arn)
                es.endpoint = details.get('Endpoint', 'n/a')
                result.append(es)
                pool[arn] = es
        parallelize(handle, out['DomainNames'])
    except Exception:
        pass

    return result


def get_dynamo_dbs(filter='.*', pool={}, env=None):
    result = []
    try:
        out = cmd_dynamodb('list_tables', env)
        out = json.loads(out)

        def handle(table):
            if re.match(filter, table):
                details = cmd_dynamodb('describe_table', 'TableName=%s' % table, env=env)
                details = json.loads(details)['Table']
                arn = details['TableArn']
                db = DynamoDB(arn)
                db.count = details['ItemCount']
                db.bytes = details['TableSizeBytes']
                db.created_at = details['CreationDateTime']
                result.append(db)
                pool[arn] = db
        parallelize(handle, out['TableNames'])
    except Exception:
        pass
    return result


def get_s3_buckets(filter='.*', pool={}, details=False, env=None):
    result = []

    def handle(bucket):
        bucket_name = bucket['Name']
        if re.match(filter, bucket_name):
            arn = 'arn:aws:s3:::%s' % bucket_name
            bucket = S3Bucket(arn)
            result.append(bucket)
            pool[arn] = bucket
            if details:
                try:
                    out = cmd_s3api('get_bucket_notification', 'Bucket=%s' % bucket_name, env=env)
                    if out:
                        out = json.loads(out)
                        if 'CloudFunctionConfiguration' in out:
                            func = out['CloudFunctionConfiguration']['CloudFunction']
                            func = EventSource.get(func, pool=pool)
                            n = S3Notification(func.id)
                            n.target = func
                            bucket.notifications.append(n)
                except Exception as e:
                    print('WARNING: Unable to get details for bucket: %s' % e)

    try:
        out = cmd_s3api('list_buckets', env=env)
        out = json.loads(out)
        parallelize(handle, out['Buckets'])
    except Exception:
        pass
    return result


def get_firehose_streams(filter='.*', pool={}, env=None):
    result = []
    try:
        out = cmd_firehose('list_delivery_streams', env=env)
        out = json.loads(out)
        for stream_name in out['DeliveryStreamNames']:
            if re.match(filter, stream_name):
                details = cmd_firehose(
                    'describe_delivery_stream', 'DeliveryStreamName=%s, Limit=1000' % stream_name, env=env)
                details = json.loads(details)['DeliveryStreamDescription']
                arn = details['DeliveryStreamARN']
                s = FirehoseStream(arn)
                for dest in details['Destinations']:
                    dest_s3 = dest['S3DestinationDescription']['BucketARN']
                    bucket = EventSource.get(dest_s3, pool=pool)
                    s.destinations.append(bucket)
                result.append(s)
    except Exception:
        pass
    return result


def read_kinesis_iterator(shard_iterator, max_results=10, env=None):
    data = cmd_kinesis('get_records', 'ShardIterator=%s, Limit=%s'
        (shard_iterator, max_results), env=env, cache_duration_secs=0)
    data = json.loads(to_str(data))
    result = data
    return result


def get_kinesis_events(stream_name, shard_id, max_results=10, env=None):
    records = []
    try:
        env = aws_stack.get_environment(env)
        records = aws_stack.kinesis_get_latest_records(stream_name, shard_id, count=max_results, env=env)
        for r in records:
            r['ApproximateArrivalTimestamp'] = mktime(r['ApproximateArrivalTimestamp'])
    except Exception:
        pass
    result = {'events': records}
    return result


def get_graph(name_filter='.*', env=None, **kwargs):
    result = {
        'nodes': [],
        'edges': []
    }

    pool = {}
    node_ids = {}

    # Make sure we load components in the right order:
    # (ES,DynamoDB,S3) -> (Kinesis,Lambda)
    domains = get_elasticsearch_domains(name_filter, pool=pool, env=env)
    dbs = get_dynamo_dbs(name_filter, pool=pool, env=env)
    buckets = get_s3_buckets(name_filter, details=True, pool=pool, env=env)
    streams = get_kinesis_streams(name_filter, pool=pool, env=env)
    firehoses = get_firehose_streams(name_filter, pool=pool, env=env)
    lambdas = get_lambda_functions(name_filter, details=True, pool=pool, env=env)
    queues = get_sqs_queues(name_filter, pool=pool, env=env)

    for es in domains:
        uid = short_uid()
        node_ids[es.id] = uid
        result['nodes'].append({'id': uid, 'arn': es.id, 'name': es.name(), 'type': 'es'})
    for b in buckets:
        uid = short_uid()
        node_ids[b.id] = uid
        result['nodes'].append({'id': uid, 'arn': b.id, 'name': b.name(), 'type': 's3'})
    for db in dbs:
        uid = short_uid()
        node_ids[db.id] = uid
        result['nodes'].append({'id': uid, 'arn': db.id, 'name': db.name(), 'type': 'dynamodb'})
    for s in streams:
        uid = short_uid()
        node_ids[s.id] = uid
        result['nodes'].append({'id': uid, 'arn': s.id, 'name': s.name(), 'type': 'kinesis'})
        for shard in s.shards:
            uid1 = short_uid()
            name = re.sub(r'shardId-0*', '', shard.id) or '0'
            result['nodes'].append({'id': uid1, 'arn': shard.id, 'name': name,
                'type': 'kinesis_shard', 'streamName': s.name(), 'parent': uid})
    for f in firehoses:
        uid = short_uid()
        node_ids[f.id] = uid
        result['nodes'].append({'id': uid, 'arn': f.id, 'name': f.name(), 'type': 'firehose'})
        for d in f.destinations:
            result['edges'].append({'source': uid, 'target': node_ids[d.id]})
    for q in queues:
        uid = short_uid()
        node_ids[q.id] = uid
        result['nodes'].append({'id': uid, 'arn': q.id, 'name': q.name(), 'type': 'sqs'})
    for lda in lambdas:
        uid = short_uid()
        node_ids[lda.id] = uid
        result['nodes'].append({'id': uid, 'arn': lda.id, 'name': lda.name(), 'type': 'lambda'})
        for s in lda.event_sources:
            lookup_id = s.id
            if isinstance(s, DynamoDBStream):
                lookup_id = s.table.id
            result['edges'].append({'source': node_ids.get(lookup_id), 'target': uid})
        for t in lda.targets:
            lookup_id = t.id
            result['edges'].append({'source': uid, 'target': node_ids.get(lookup_id)})
    for b in buckets:
        for n in b.notifications:
            src_uid = node_ids[b.id]
            tgt_uid = node_ids[n.target.id]
            result['edges'].append({'source': src_uid, 'target': tgt_uid})

    return result
