import time
import json


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
        return '<%s:%s>' % (self.__class__.__name__, self.id)


class KinesisStream(Component):
    def __init__(self, id, params={}, num_shards=1, connection=None):
        super(KinesisStream, self).__init__(id)
        self.shards = []
        self.stream_name = params['name'] if 'name' in params else self.name()
        self.num_shards = params['shards'] if 'shards' in params else num_shards
        self.conn = connection
        self.stream_info = params

    def name(self):
        return self.id.split(':stream/')[-1]

    def connect(self, connection):
        self.conn = connection

    def describe(self):
        r = self.conn.describe_stream(StreamName=self.stream_name)
        return r.get('StreamDescription')

    def create(self, raise_on_error=False):
        try:
            self.conn.create_stream(StreamName=self.stream_name, ShardCount=self.num_shards)
        except Exception, e:
            # TODO catch stream already exists exception, otherwise rethrow
            if raise_on_error:
                raise e

    def get_status(self):
        description = self.describe()
        return description.get('StreamStatus')

    def put(self, data, key):
        if not isinstance(data, str):
            data = json.dumps(data)
        return self.conn.put_record(StreamName=self.stream_name, Data=data, PartitionKey=key)

    def read(self, amount=-1, shard='shardId-000000000001'):
        s_iterator = kinesis_conn.get_shard_iterator(self.stream_name, shard, 'TRIM_HORIZON')
        record = kinesis_conn.get_records(s_iterator['ShardIterator'])
        while True:
            try:
                if record['NextShardIterator'] is None:
                    break
                else:
                    next_entry = kinesis_conn.get_records(record['NextShardIterator'])
                    if len(next_entry['Records']):
                        print next_entry['Records'][0]['Data']
                    record = next_entry
            except:
                print 'an exception has occured'

    def wait_for(self):
        GET_STATUS_SLEEP_SECS = 5
        GET_STATUS_RETRIES = 50
        for i in range(0, GET_STATUS_RETRIES):
            try:
                status = self.get_status()
                if status == 'ACTIVE':
                    return
            except Exception, e:
                # swallowing this exception should be ok, as we are in a retry loop
                pass
            time.sleep(GET_STATUS_SLEEP_SECS)
        raise Exception('Failed to get active status for stream "%s", giving up' % self.stream_name)

    def destroy(self):
        self.conn.delete_stream(StreamName=self.stream_name)


class KinesisShard(Component):
    MAX_KEY = "340282366920938463463374607431768211455"

    def __init__(self, id):
        super(KinesisShard, self).__init__(id)
        self.stream = None
        self.start_key = "0"
        self.end_key = KinesisShard.MAX_KEY  # 128 times '1' binary as decimal
        self.child_shards = []

    def print_tree(self, indent=''):
        print '%s%s' % (indent, self)
        for c in self.child_shards:
            c.print_tree(indent=indent + '   ')

    def length(self):
        return long(self.end_key) - long(self.start_key)

    def percent(self):
        return 100.0 * self.length() / float(KinesisShard.MAX_KEY)

    def __str__(self):
        return ('Shard(%s, length=%s, percent=%s, start=%s, end=%s)' %
                (self.id, self.length(), self.percent(), self.start_key,
                    self.end_key))

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
        return self.id.split(':deliverystream/')[-1]


class LambdaFunction(Component):
    def __init__(self, id):
        super(LambdaFunction, self).__init__(id)
        self.event_sources = []
        self.targets = []

    def name(self):
        return self.id.split(':function:')[-1]

    def __str__(self):
        return '<%s:%s>' % (self.__class__.__name__, self.name())


class DynamoDB(Component):
    def __init__(self, id, env=None):
        super(DynamoDB, self).__init__(id, env=env)
        self.count = -1
        self.bytes = -1

    def name(self):
        return self.id.split(':table/')[-1]


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
        return (other.table == self.table and
            other.id == self.id and
            other.keys == self.keys)

    def __hash__(self):
        return hash(self.table) + hash(self.id) + hash(self.keys)


class ElasticSearch(Component):
    def __init__(self, id):
        super(ElasticSearch, self).__init__(id)
        self.indexes = []
        self.endpoint = None

    def name(self):
        return self.id.split(':domain/')[-1]


class S3Bucket(Component):
    def __init__(self, id):
        super(S3Bucket, self).__init__(id)
        self.notifications = []

    def name(self):
        return self.id.split('arn:aws:s3:::')[-1]


class S3Notification(Component):
    def __init__(self, id):
        super(S3Notification, self).__init__(id)
        self.target = None
        self.trigger = None


class EventSource(Component):
    def __init__(self, id):
        super(EventSource, self).__init__(id)

    @staticmethod
    def get(obj, pool={}, type=None):
        if not obj:
            return None
        if isinstance(obj, Component):
            obj = obj.id
        if obj in pool:
            return pool[obj]
        inst = None
        if obj.startswith('arn:aws:kinesis:'):
            inst = KinesisStream(obj)
        if obj.startswith('arn:aws:lambda:'):
            inst = LambdaFunction(obj)
        elif obj.startswith('arn:aws:dynamodb:'):
            if '/stream/' in obj:
                table_id = obj.split('/stream/')[0]
                table = DynamoDB(table_id)
                inst = DynamoDBStream(obj)
                inst.table = table
            else:
                inst = DynamoDB(obj)
        elif type:
            for o in EventSource.filter_type(pool, type):
                if o.name() == obj:
                    return o
                if type == ElasticSearch:
                    if o.endpoint == obj:
                        return o
        else:
            print("Unexpected object name! %s" % obj)
        return inst

    @staticmethod
    def filter_type(pool, type):
        result = []
        for key, obj in pool.iteritems():
            if isinstance(obj, type):
                result.append(obj)
        return result
