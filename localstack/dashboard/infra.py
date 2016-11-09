from localstack.utils.common import *
from localstack.utils.aws.aws_models import *
import re
import sh
import json
import logging
import base64

AWS_CACHE_TIMEOUT = 60 * 60  # TODO fix
AWS_LAMBDA_CODE_CACHE_TIMEOUT = 30 * 60  # TODO fix
MOCK_OBJ = False
TMP_DOWNLOAD_FILE_PATTERN = '/tmp/tmpfile.*'
TMP_DOWNLOAD_CACHE_MAX_AGE = 30 * 60
last_cache_cleanup_time = {'time': 0}

# logger
LOG = logging.getLogger(__name__)


def get_kinesis_streams(filter='.*', pool={}):
    if MOCK_OBJ:
        return []
    out = run('aws kinesis list-streams', cache_duration_secs=AWS_CACHE_TIMEOUT)
    out = json.loads(out)
    result = []
    for name in out['StreamNames']:
        if re.match(filter, name):
            details = run('aws kinesis describe-stream --stream-name %s' % name,
                cache_duration_secs=AWS_CACHE_TIMEOUT)
            details = json.loads(details)
            arn = details['StreamDescription']['StreamARN']
            stream = KinesisStream(arn)
            pool[arn] = stream
            stream.shards = get_kinesis_shards(stream_details=details)
            result.append(stream)
    return result


def get_kinesis_shards(stream_name=None, stream_details=None):
    if not stream_details:
        out = run('aws kinesis describe-stream --stream-name %s' % stream_name,
            cache_duration_secs=AWS_CACHE_TIMEOUT)
        stream_details = json.loads(out)
    shards = stream_details['StreamDescription']['Shards']
    result = []
    for s in shards:
        shard = KinesisShard(s['ShardId'])
        shard.start_key = s['HashKeyRange']['StartingHashKey']
        shard.end_key = s['HashKeyRange']['EndingHashKey']
        result.append(shard)
    return result


def resolve_string_or_variable(string, code_map):
    if re.match(r'^["\'].*["\']$', string):
        return string.replace('"', '').replace("'", '')
    LOG.warning("Variable resolution not implemented")
    return None


def extract_endpoints(code_map, pool={}):
    result = []
    identifiers = []
    for key, code in code_map.iteritems():
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


def get_lambda_functions(filter='.*', details=False, pool={}):
    if MOCK_OBJ:
        return []
    out = run('aws lambda list-functions', cache_duration_secs=AWS_CACHE_TIMEOUT)
    out = json.loads(out)
    result = []

    def handle(func):
        func_name = func['FunctionName']
        print("Handling function %s" % func_name)
        if re.match(filter, func_name):
            arn = func['FunctionArn']
            f = LambdaFunction(arn)
            pool[arn] = f
            result.append(f)
            if details:
                sources = get_lambda_event_sources(f.name())
                for src in sources:
                    arn = src['EventSourceArn']
                    f.event_sources.append(EventSource.get(arn, pool=pool))
                try:
                    code_map = get_lambda_code(func_name)
                    f.targets = extract_endpoints(code_map, pool)
                except Exception, e:
                    LOG.warning("Unable to get code for lambda '%s'" % func_name)
    parallelize(handle, out['Functions'])
    # print result
    return result


def get_lambda_event_sources(func_name=None):
    if MOCK_OBJ:
        return {}

    cmd = 'aws lambda list-event-source-mappings'
    if func_name:
        cmd = '%s --function-name %s' % (cmd, func_name)
    out = run(cmd, cache_duration_secs=AWS_CACHE_TIMEOUT)
    out = json.loads(out)
    result = out['EventSourceMappings']
    return result


def get_lambda_code(func_name, retries=1, cache_time=AWS_LAMBDA_CODE_CACHE_TIMEOUT):
    if MOCK_OBJ:
        return ''
    cmd = 'aws lambda get-function --function-name %s' % func_name
    out = run(cmd, cache_duration_secs=cache_time)
    out = json.loads(out)
    loc = out['Code']['Location']
    hash = md5(loc)
    # print("Location %s %s" % (hash, func_name))
    folder = TMP_DOWNLOAD_FILE_PATTERN.replace('*', '%s') % hash
    filename = 'archive.zip'
    archive = '%s/%s' % (folder, filename)
    try:
        run('mkdir -p %s' % folder)
        if not os.path.isfile(archive):
            print("Downloading %s" % archive)
            run("wget -O %s '%s'" % (archive, loc))
        if len(os.listdir(folder)) <= 1:
            print("Unzipping %s/%s" % (folder, filename))
            run("cd %s && unzip -o %s" % (folder, filename))
    except Exception, e:
        print("WARN: %s" % e)
        sh.rm('-f', archive)
        if retries > 0:
            return get_lambda_code(func_name, retries=retries - 1, cache_time=1)
        else:
            print("WARNING: Unable to retrieve lambda code: %s" % e)

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

    return result


def get_elasticsearch_domains(filter='.*', pool={}):
    out = run('aws es list-domain-names', cache_duration_secs=AWS_CACHE_TIMEOUT)
    out = json.loads(out)
    result = []

    def handle(domain):
        domain = domain['DomainName']
        if re.match(filter, domain):
            details = run('aws es describe-elasticsearch-domain --domain-name %s' % domain,
                cache_duration_secs=AWS_CACHE_TIMEOUT)
            details = json.loads(details)['DomainStatus']
            arn = details['ARN']
            es = ElasticSearch(arn)
            es.endpoint = details['Endpoint']
            result.append(es)
            pool[arn] = es
    parallelize(handle, out['DomainNames'])
    return result


def get_dynamo_dbs(filter='.*', pool={}):
    out = run('aws dynamodb list-tables', cache_duration_secs=AWS_CACHE_TIMEOUT)
    out = json.loads(out)
    result = []

    def handle(table):
        if re.match(filter, table):
            details = run('aws dynamodb describe-table --table-name %s' % table,
                cache_duration_secs=AWS_CACHE_TIMEOUT)
            details = json.loads(details)['Table']
            arn = details['TableArn']
            db = DynamoDB(arn)
            db.count = details['ItemCount']
            db.bytes = details['TableSizeBytes']
            db.created_at = details['CreationDateTime']
            result.append(db)
            pool[arn] = db
    parallelize(handle, out['TableNames'])
    return result


def get_s3_buckets(filter='.*', pool={}, details=False):
    out = run('aws s3api list-buckets', cache_duration_secs=AWS_CACHE_TIMEOUT)
    out = json.loads(out)
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
                    out = run('aws s3api get-bucket-notification --bucket %s' % bucket_name,
                        cache_duration_secs=AWS_CACHE_TIMEOUT)
                    if out:
                        out = json.loads(out)
                        if 'CloudFunctionConfiguration' in out:
                            func = out['CloudFunctionConfiguration']['CloudFunction']
                            func = EventSource.get(func, pool=pool)
                            n = S3Notification(func.id)
                            n.target = func
                            bucket.notifications.append(n)
                except Exception, e:
                    print("WARNING: Unable to get details for bucket: %s" % e)
    parallelize(handle, out['Buckets'])
    return result


def get_firehose_streams(filter='.*', pool={}):
    out = run('aws firehose list-delivery-streams', cache_duration_secs=AWS_CACHE_TIMEOUT)
    out = json.loads(out)
    result = []
    for stream_name in out['DeliveryStreamNames']:
        if re.match(filter, stream_name):
            details = run(
                'aws firehose describe-delivery-stream --delivery-stream-name %s' % stream_name,
                cache_duration_secs=AWS_CACHE_TIMEOUT)
            details = json.loads(details)['DeliveryStreamDescription']
            arn = details['DeliveryStreamARN']
            s = FirehoseStream(arn)
            for dest in details['Destinations']:
                dest_s3 = dest['S3DestinationDescription']['BucketARN']
                bucket = func = EventSource.get(dest_s3, pool=pool)
                s.destinations.append(bucket)
            result.append(s)
    return result


def read_kinesis_iterator(shard_iterator, max_results=10):
    data = run('aws kinesis get-records --shard-iterator %s --limit %s' %
        (shard_iterator, max_results))
    data = json.loads(data)
    result = data
    return result


def get_kinesis_events(stream_name, shard_id, max_results=10):
    cmd = ('aws kinesis get-shard-iterator --stream-name %s --shard-id %s ' +
        '--shard-iterator-type LATEST') % (stream_name, shard_id)
    out = run(cmd)
    out = json.loads(out)
    shard_iter = out['ShardIterator']
    data = read_kinesis_iterator(shard_iter, max_results)
    result = data['Records']
    if len(result) <= 0:
        next_iter = data['NextShardIterator']
        data = read_kinesis_iterator(next_iter, max_results)
        result = data['Records']
    for r in result:
        r['Data'] = base64.b64decode(r['Data'])
        r['Data'] = remove_non_ascii(r['Data'])
    result = {
        'events': result
    }
    return result


def get_graph(name_filter='.*'):
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
        domains = get_elasticsearch_domains(name_filter, pool=pool)
        dbs = get_dynamo_dbs(name_filter, pool=pool)
        buckets = get_s3_buckets(name_filter, details=True, pool=pool)
        streams = get_kinesis_streams(name_filter, pool=pool)
        firehoses = get_firehose_streams(name_filter, pool=pool)
        lambdas = get_lambda_functions(name_filter, details=True, pool=pool)

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
                name = re.sub(r'shardId-0*', '', shard.id)
                result['nodes'].append({'id': uid1, 'arn': shard.id, 'name': name,
                    'type': 'kinesis_shard', 'streamName': s.name(), 'parent': uid})
        for f in firehoses:
            uid = short_uid()
            node_ids[f.id] = uid
            result['nodes'].append({'id': uid, 'arn': f.id, 'name': f.name(), 'type': 'firehose'})
            for d in f.destinations:
                result['edges'].append({'source': uid, 'target': node_ids[d.id]})
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
        print json.dumps(result)

    return result
