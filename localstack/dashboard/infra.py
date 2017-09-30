import re
import os
import json
import logging
import socket
import tempfile
from localstack.utils.common import (short_uid, parallelize, is_port_open,
    rm_rf, unzip, download, clean_cache, mktime, load_file, mkdir, run, md5)
from localstack.utils.aws.aws_models import (ElasticSearch, S3Notification,
    EventSource, DynamoDB, DynamoDBStream, FirehoseStream, S3Bucket, SqsQueue,
    KinesisShard, KinesisStream, LambdaFunction)
from localstack.utils.aws import aws_stack
from localstack.constants import REGION_LOCAL, DEFAULT_REGION
from six import iteritems


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


def run_cached(cmd, cache_duration_secs=None):
    if cache_duration_secs is None:
        cache_duration_secs = AWS_CACHE_TIMEOUT
    env_vars = os.environ.copy()
    env_vars.update({
        'AWS_ACCESS_KEY_ID': os.environ.get('AWS_ACCESS_KEY_ID') or 'foobar',
        'AWS_SECRET_ACCESS_KEY': os.environ.get('AWS_SECRET_ACCESS_KEY') or 'foobar',
        'AWS_DEFAULT_REGION': os.environ.get('AWS_DEFAULT_REGION') or DEFAULT_REGION,
        'PYTHONWARNINGS': 'ignore:Unverified HTTPS request'
    })
    return run(cmd, cache_duration_secs=cache_duration_secs, env_vars=env_vars)


def run_aws_cmd(service, cmd_params, env=None, cache_duration_secs=None):
    cmd = '%s %s' % (aws_cmd(service, env), cmd_params)
    return run_cached(cmd, cache_duration_secs=cache_duration_secs)


def cmd_s3api(cmd_params, env):
    return run_aws_cmd('s3api', cmd_params, env)


def cmd_es(cmd_params, env):
    return run_aws_cmd('es', cmd_params, env)


def cmd_kinesis(cmd_params, env, cache_duration_secs=None):
    return run_aws_cmd('kinesis', cmd_params, env,
        cache_duration_secs=cache_duration_secs)


def cmd_dynamodb(cmd_params, env):
    return run_aws_cmd('dynamodb', cmd_params, env)


def cmd_firehose(cmd_params, env):
    return run_aws_cmd('firehose', cmd_params, env)


def cmd_sqs(cmd_params, env):
    return run_aws_cmd('sqs', cmd_params, env)


def cmd_lambda(cmd_params, env, cache_duration_secs=None):
    return run_aws_cmd('lambda', cmd_params, env,
        cache_duration_secs=cache_duration_secs)


def aws_cmd(service, env):
    # TODO: use boto3 instead of running aws-cli commands here!

    cmd = '{ test `which aws` || . .venv/bin/activate; }; aws'
    endpoint_url = None
    env = aws_stack.get_environment(env)
    if env.region == REGION_LOCAL:
        endpoint_url = aws_stack.get_local_service_url(service)
    if endpoint_url:
        if endpoint_url.startswith('https://'):
            cmd += ' --no-verify-ssl'
        cmd = '%s --endpoint-url="%s"' % (cmd, endpoint_url)
        if not is_port_open(endpoint_url):
            raise socket.error()
    cmd = '%s %s' % (cmd, service)
    return cmd


def get_kinesis_streams(filter='.*', pool={}, env=None):
    if MOCK_OBJ:
        return []
    result = []
    try:
        out = cmd_kinesis('list-streams', env)
        out = json.loads(out)
        for name in out['StreamNames']:
            if re.match(filter, name):
                details = cmd_kinesis('describe-stream --stream-name %s' % name, env=env)
                details = json.loads(details)
                arn = details['StreamDescription']['StreamARN']
                stream = KinesisStream(arn)
                pool[arn] = stream
                stream.shards = get_kinesis_shards(stream_details=details, env=env)
                result.append(stream)
    except socket.error:
        pass
    return result


def get_kinesis_shards(stream_name=None, stream_details=None, env=None):
    if not stream_details:
        out = cmd_kinesis('describe-stream --stream-name %s' % stream_name, env)
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
        out = cmd_sqs('list-queues', env)
        if not out.strip():
            return result
        queues = json.loads(out)['QueueUrls']
        for q in queues:
            name = q.split('/')[-1]
            account = q.split('/')[-2]
            arn = 'arn:aws:sqs:%s:%s:%s' % (DEFAULT_REGION, account, name)
            if re.match(filter, name):
                queue = SqsQueue(arn)
                result.append(queue)
    except socket.error:
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
        out = cmd_lambda('list-functions', env)
        out = json.loads(out)
        parallelize(handle, out['Functions'])
    except socket.error:
        pass
    return result


def get_lambda_event_sources(func_name=None, env=None):
    if MOCK_OBJ:
        return {}

    cmd = 'list-event-source-mappings'
    if func_name:
        cmd = '%s --function-name %s' % (cmd, func_name)
    out = cmd_lambda(cmd, env=env)
    out = json.loads(out)
    result = out['EventSourceMappings']
    return result


def get_lambda_code(func_name, retries=1, cache_time=None, env=None):
    if MOCK_OBJ:
        return ''
    env = aws_stack.get_environment(env)
    if cache_time is None and env.region != REGION_LOCAL:
        cache_time = AWS_LAMBDA_CODE_CACHE_TIMEOUT
    out = cmd_lambda('get-function --function-name %s' % func_name, env, cache_time)
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
        out = cmd_es('list-domain-names', env)
        out = json.loads(out)

        def handle(domain):
            domain = domain['DomainName']
            if re.match(filter, domain):
                details = cmd_es('describe-elasticsearch-domain --domain-name %s' % domain, env)
                details = json.loads(details)['DomainStatus']
                arn = details['ARN']
                es = ElasticSearch(arn)
                es.endpoint = details['Endpoint']
                result.append(es)
                pool[arn] = es
        parallelize(handle, out['DomainNames'])
    except socket.error:
        pass

    return result


def get_dynamo_dbs(filter='.*', pool={}, env=None):
    result = []
    try:
        out = cmd_dynamodb('list-tables', env)
        out = json.loads(out)

        def handle(table):
            if re.match(filter, table):
                details = cmd_dynamodb('describe-table --table-name %s' % table, env)
                details = json.loads(details)['Table']
                arn = details['TableArn']
                db = DynamoDB(arn)
                db.count = details['ItemCount']
                db.bytes = details['TableSizeBytes']
                db.created_at = details['CreationDateTime']
                result.append(db)
                pool[arn] = db
        parallelize(handle, out['TableNames'])
    except socket.error:
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
                    out = cmd_s3api('get-bucket-notification-configuration --bucket %s' % bucket_name, env=env)
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
        out = cmd_s3api('list-buckets', env)
        out = json.loads(out)
        parallelize(handle, out['Buckets'])
    except socket.error:
        pass
    return result


def get_firehose_streams(filter='.*', pool={}, env=None):
    result = []
    try:
        out = cmd_firehose('list-delivery-streams', env)
        out = json.loads(out)
        for stream_name in out['DeliveryStreamNames']:
            if re.match(filter, stream_name):
                details = cmd_firehose(
                    'describe-delivery-stream --delivery-stream-name %s' % stream_name, env)
                details = json.loads(details)['DeliveryStreamDescription']
                arn = details['DeliveryStreamARN']
                s = FirehoseStream(arn)
                for dest in details['Destinations']:
                    dest_s3 = dest['S3DestinationDescription']['BucketARN']
                    bucket = EventSource.get(dest_s3, pool=pool)
                    s.destinations.append(bucket)
                result.append(s)
    except socket.error:
        pass
    return result


def read_kinesis_iterator(shard_iterator, max_results=10, env=None):
    data = cmd_kinesis('get-records --shard-iterator %s --limit %s' %
        (shard_iterator, max_results), env, cache_duration_secs=0)
    data = json.loads(data)
    result = data
    return result


def get_kinesis_events(stream_name, shard_id, max_results=10, env=None):
    env = aws_stack.get_environment(env)
    records = aws_stack.kinesis_get_latest_records(stream_name, shard_id, count=max_results, env=env)
    for r in records:
        r['ApproximateArrivalTimestamp'] = mktime(r['ApproximateArrivalTimestamp'])
    result = {
        'events': records
    }
    return result


def get_graph(name_filter='.*', env=None):
    result = {
        'nodes': [],
        'edges': []
    }

    pool = {}

    if True:
        result = {
            'nodes': [],
            'edges': []
        }
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
        for l in lambdas:
            uid = short_uid()
            node_ids[l.id] = uid
            result['nodes'].append({'id': uid, 'arn': l.id, 'name': l.name(), 'type': 'lambda'})
            for s in l.event_sources:
                lookup_id = s.id
                if isinstance(s, DynamoDBStream):
                    lookup_id = s.table.id
                result['edges'].append({'source': node_ids.get(lookup_id), 'target': uid})
            for t in l.targets:
                lookup_id = t.id
                result['edges'].append({'source': uid, 'target': node_ids.get(lookup_id)})
        for b in buckets:
            for n in b.notifications:
                src_uid = node_ids[b.id]
                tgt_uid = node_ids[n.target.id]
                result['edges'].append({'source': src_uid, 'target': tgt_uid})

    return result
