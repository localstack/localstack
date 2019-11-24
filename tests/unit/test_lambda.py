import os
import re
import json
import unittest
from localstack.utils.common import save_file, new_tmp_dir, mkdir
from localstack.services.awslambda import lambda_api, lambda_executors
from localstack.utils.aws.aws_models import LambdaFunction


class TestLambdaAPI(unittest.TestCase):
    CODE_SIZE = 50
    CODE_SHA_256 = '/u60ZpAA9bzZPVwb8d4390i5oqP1YAObUwV03CZvsWA='
    MEMORY_SIZE = 128
    ROLE = 'arn:aws:iam::123456:role/role-name'
    LAST_MODIFIED = '2019-05-25T17:00:48.260+0000'
    TRACING_CONFIG = {'Mode': 'PassThrough'}
    REVISION_ID = 'e54dbcf8-e3ef-44ab-9af7-8dbef510608a'
    HANDLER = 'index.handler'
    RUNTIME = 'node.js4.3'
    TIMEOUT = 60  # Default value, hardcoded
    FUNCTION_NAME = 'test1'
    ALIAS_NAME = 'alias1'
    ALIAS2_NAME = 'alias2'
    RESOURCENOTFOUND_EXCEPTION = 'ResourceNotFoundException'
    RESOURCENOTFOUND_MESSAGE = 'Function not found: %s'
    ALIASEXISTS_EXCEPTION = 'ResourceConflictException'
    ALIASEXISTS_MESSAGE = 'Alias already exists: %s'
    ALIASNOTFOUND_EXCEPTION = 'ResourceNotFoundException'
    ALIASNOTFOUND_MESSAGE = 'Alias not found: %s'
    TEST_UUID = 'Test'
    TAGS = {'hello': 'world', 'env': 'prod'}

    def setUp(self):
        lambda_api.cleanup()
        self.maxDiff = None
        self.app = lambda_api.app
        self.app.testing = True
        self.client = self.app.test_client()

    def test_get_non_existent_function_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.get_function('non_existent_function_name').get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(
                self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn('non_existent_function_name'),
                result['message'])

    def test_get_event_source_mapping(self):
        with self.app.test_request_context():
            lambda_api.event_source_mappings.append({'UUID': self.TEST_UUID})
            result = lambda_api.get_event_source_mapping(self.TEST_UUID)
            self.assertEqual(json.loads(result.get_data()).get('UUID'), self.TEST_UUID)

    def test_get_event_sources(self):
        with self.app.test_request_context():
            lambda_api.event_source_mappings.append(
                {
                    'UUID': self.TEST_UUID,
                    'EventSourceArn': 'the_arn'
                })

            # Match source ARN
            result = lambda_api.get_event_sources(source_arn='the_arn')
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].get('UUID'), self.TEST_UUID)

            # No partial match on source ARN
            result = lambda_api.get_event_sources(source_arn='the_')
            self.assertEqual(len(result), 0)

    def test_get_event_sources_with_paths(self):
        with self.app.test_request_context():
            lambda_api.event_source_mappings.append(
                {
                    'UUID': self.TEST_UUID,
                    'EventSourceArn': 'the_arn/path/subpath'
                })

            # Do partial match on paths
            result = lambda_api.get_event_sources(source_arn='the_arn')
            self.assertEqual(len(result), 1)
            result = lambda_api.get_event_sources(source_arn='the_arn/path')
            self.assertEqual(len(result), 1)

    def test_delete_event_source_mapping(self):
        with self.app.test_request_context():
            lambda_api.event_source_mappings.append({'UUID': self.TEST_UUID})
            result = lambda_api.delete_event_source_mapping(self.TEST_UUID)
            self.assertEqual(json.loads(result.get_data()).get('UUID'), self.TEST_UUID)
            self.assertEqual(0, len(lambda_api.event_source_mappings))

    def test_create_event_source_mapping(self):
        self.client.post('{0}/event-source-mappings/'.format(lambda_api.PATH_ROOT),
            data=json.dumps({'FunctionName': 'test-lambda-function', 'EventSourceArn': 'fake-arn'}))

        listResponse = self.client.get('{0}/event-source-mappings/'.format(lambda_api.PATH_ROOT))
        listResult = json.loads(listResponse.get_data())

        eventSourceMappings = listResult.get('EventSourceMappings')

        self.assertEqual(1, len(eventSourceMappings))
        self.assertEqual('Enabled', eventSourceMappings[0]['State'])

    def test_create_disabled_event_source_mapping(self):
        createResponse = self.client.post('{0}/event-source-mappings/'.format(lambda_api.PATH_ROOT),
                            data=json.dumps({'FunctionName': 'test-lambda-function',
                                             'EventSourceArn': 'fake-arn',
                                             'Enabled': 'false'}))
        createResult = json.loads(createResponse.get_data())

        self.assertEqual('Disabled', createResult['State'])

        getResponse = self.client.get('{0}/event-source-mappings/{1}'.format(lambda_api.PATH_ROOT,
                        createResult.get('UUID')))
        getResult = json.loads(getResponse.get_data())

        self.assertEqual('Disabled', getResult['State'])

    def test_update_event_source_mapping(self):
        createResponse = self.client.post('{0}/event-source-mappings/'.format(lambda_api.PATH_ROOT),
                            data=json.dumps({'FunctionName': 'test-lambda-function',
                                             'EventSourceArn': 'fake-arn',
                                             'Enabled': 'true'}))
        createResult = json.loads(createResponse.get_data())

        putResponse = self.client.put('{0}/event-source-mappings/{1}'.format(lambda_api.PATH_ROOT,
                        createResult.get('UUID')), data=json.dumps({'Enabled': 'false'}))
        putResult = json.loads(putResponse.get_data())

        self.assertEqual('Disabled', putResult['State'])

        getResponse = self.client.get('{0}/event-source-mappings/{1}'.format(lambda_api.PATH_ROOT,
                        createResult.get('UUID')))
        getResult = json.loads(getResponse.get_data())

        self.assertEqual('Disabled', getResult['State'])

    def test_publish_function_version(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)

            result = json.loads(lambda_api.publish_version(self.FUNCTION_NAME).get_data())
            result2 = json.loads(lambda_api.publish_version(self.FUNCTION_NAME).get_data())
            result.pop('RevisionId', None)  # we need to remove this, since this is random, so we cannot know its value
            result2.pop('RevisionId', None)  # we need to remove this, since this is random, so we cannot know its value

            expected_result = dict()
            expected_result['CodeSize'] = self.CODE_SIZE
            expected_result['CodeSha256'] = self.CODE_SHA_256
            expected_result['FunctionArn'] = str(lambda_api.func_arn(self.FUNCTION_NAME)) + ':1'
            expected_result['FunctionName'] = str(self.FUNCTION_NAME)
            expected_result['Handler'] = str(self.HANDLER)
            expected_result['Runtime'] = str(self.RUNTIME)
            expected_result['Timeout'] = self.TIMEOUT
            expected_result['Description'] = ''
            expected_result['MemorySize'] = self.MEMORY_SIZE
            expected_result['Role'] = self.ROLE
            expected_result['LastModified'] = self.LAST_MODIFIED
            expected_result['TracingConfig'] = self.TRACING_CONFIG
            expected_result['Version'] = '1'
            expected_result2 = dict(expected_result)
            expected_result2['FunctionArn'] = str(lambda_api.func_arn(self.FUNCTION_NAME)) + ':2'
            expected_result2['Version'] = '2'
            self.assertDictEqual(expected_result, result)
            self.assertDictEqual(expected_result2, result2)

    def test_publish_non_existant_function_version_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.publish_version(self.FUNCTION_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                             result['message'])

    def test_list_function_versions(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            lambda_api.publish_version(self.FUNCTION_NAME)
            lambda_api.publish_version(self.FUNCTION_NAME)

            result = json.loads(lambda_api.list_versions(self.FUNCTION_NAME).get_data())
            for version in result['Versions']:
                # we need to remove this, since this is random, so we cannot know its value
                version.pop('RevisionId', None)

            latest_version = dict()
            latest_version['CodeSize'] = self.CODE_SIZE
            latest_version['CodeSha256'] = self.CODE_SHA_256
            latest_version['FunctionArn'] = str(lambda_api.func_arn(self.FUNCTION_NAME)) + ':$LATEST'
            latest_version['FunctionName'] = str(self.FUNCTION_NAME)
            latest_version['Handler'] = str(self.HANDLER)
            latest_version['Runtime'] = str(self.RUNTIME)
            latest_version['Timeout'] = self.TIMEOUT
            latest_version['Description'] = ''
            latest_version['MemorySize'] = self.MEMORY_SIZE
            latest_version['Role'] = self.ROLE
            latest_version['LastModified'] = self.LAST_MODIFIED
            latest_version['TracingConfig'] = self.TRACING_CONFIG
            latest_version['Version'] = '$LATEST'
            version1 = dict(latest_version)
            version1['FunctionArn'] = str(lambda_api.func_arn(self.FUNCTION_NAME)) + ':1'
            version1['Version'] = '1'
            version2 = dict(latest_version)
            version2['FunctionArn'] = str(lambda_api.func_arn(self.FUNCTION_NAME)) + ':2'
            version2['Version'] = '2'
            expected_result = {'Versions': sorted([latest_version, version1, version2],
                                                  key=lambda k: str(k.get('Version')))}
            self.assertDictEqual(expected_result, result)

    def test_list_non_existant_function_versions_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.list_versions(self.FUNCTION_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                             result['message'])

    def test_create_alias(self):
        self._create_function(self.FUNCTION_NAME)
        self.client.post('{0}/functions/{1}/versions'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME))

        response = self.client.post('{0}/functions/{1}/aliases'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME),
                         data=json.dumps({'Name': self.ALIAS_NAME, 'FunctionVersion': '1',
                             'Description': ''}))
        result = json.loads(response.get_data())
        result.pop('RevisionId', None)  # we need to remove this, since this is random, so we cannot know its value

        expected_result = {'AliasArn': lambda_api.func_arn(self.FUNCTION_NAME) + ':' + self.ALIAS_NAME,
                           'FunctionVersion': '1', 'Description': '', 'Name': self.ALIAS_NAME}
        self.assertDictEqual(expected_result, result)

    def test_create_alias_on_non_existant_function_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.create_alias(self.FUNCTION_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                             result['message'])

    def test_create_alias_returns_error_if_already_exists(self):
        self._create_function(self.FUNCTION_NAME)
        self.client.post('{0}/functions/{1}/versions'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME))
        data = json.dumps({'Name': self.ALIAS_NAME, 'FunctionVersion': '1', 'Description': ''})
        self.client.post('{0}/functions/{1}/aliases'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME), data=data)

        response = self.client.post('{0}/functions/{1}/aliases'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME),
                                    data=data)
        result = json.loads(response.get_data())

        alias_arn = lambda_api.func_arn(self.FUNCTION_NAME) + ':' + self.ALIAS_NAME
        self.assertEqual(self.ALIASEXISTS_EXCEPTION, result['__type'])
        self.assertEqual(self.ALIASEXISTS_MESSAGE % alias_arn,
                         result['message'])

    def test_update_alias(self):
        self._create_function(self.FUNCTION_NAME)
        self.client.post('{0}/functions/{1}/versions'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME))
        self.client.post('{0}/functions/{1}/aliases'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME),
                         data=json.dumps({
                             'Name': self.ALIAS_NAME, 'FunctionVersion': '1', 'Description': ''}))

        response = self.client.put('{0}/functions/{1}/aliases/{2}'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME,
                                                                          self.ALIAS_NAME),
                                   data=json.dumps({'FunctionVersion': '$LATEST', 'Description': 'Test-Description'}))
        result = json.loads(response.get_data())
        result.pop('RevisionId', None)  # we need to remove this, since this is random, so we cannot know its value

        expected_result = {'AliasArn': lambda_api.func_arn(self.FUNCTION_NAME) + ':' + self.ALIAS_NAME,
                           'FunctionVersion': '$LATEST', 'Description': 'Test-Description',
                           'Name': self.ALIAS_NAME}
        self.assertDictEqual(expected_result, result)

    def test_update_alias_on_non_existant_function_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.update_alias(self.FUNCTION_NAME, self.ALIAS_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                             result['message'])

    def test_update_alias_on_non_existant_alias_returns_error(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            result = json.loads(lambda_api.update_alias(self.FUNCTION_NAME, self.ALIAS_NAME).get_data())
            alias_arn = lambda_api.func_arn(self.FUNCTION_NAME) + ':' + self.ALIAS_NAME
            self.assertEqual(self.ALIASNOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(self.ALIASNOTFOUND_MESSAGE % alias_arn, result['message'])

    def test_get_alias(self):
        self._create_function(self.FUNCTION_NAME)
        self.client.post('{0}/functions/{1}/versions'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME))
        self.client.post('{0}/functions/{1}/aliases'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME),
                         data=json.dumps({
                             'Name': self.ALIAS_NAME, 'FunctionVersion': '1', 'Description': ''}))

        response = self.client.get('{0}/functions/{1}/aliases/{2}'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME,
                                                                          self.ALIAS_NAME))
        result = json.loads(response.get_data())
        result.pop('RevisionId', None)  # we need to remove this, since this is random, so we cannot know its value

        expected_result = {'AliasArn': lambda_api.func_arn(self.FUNCTION_NAME) + ':' + self.ALIAS_NAME,
                           'FunctionVersion': '1', 'Description': '',
                           'Name': self.ALIAS_NAME}
        self.assertDictEqual(expected_result, result)

    def test_get_alias_on_non_existant_function_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.get_alias(self.FUNCTION_NAME, self.ALIAS_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                             result['message'])

    def test_get_alias_on_non_existant_alias_returns_error(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            result = json.loads(lambda_api.get_alias(self.FUNCTION_NAME, self.ALIAS_NAME).get_data())
            alias_arn = lambda_api.func_arn(self.FUNCTION_NAME) + ':' + self.ALIAS_NAME
            self.assertEqual(self.ALIASNOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(self.ALIASNOTFOUND_MESSAGE % alias_arn, result['message'])

    def test_list_aliases(self):
        self._create_function(self.FUNCTION_NAME)
        self.client.post('{0}/functions/{1}/versions'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME))

        self.client.post('{0}/functions/{1}/aliases'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME),
                         data=json.dumps({'Name': self.ALIAS2_NAME, 'FunctionVersion': '$LATEST'}))
        self.client.post('{0}/functions/{1}/aliases'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME),
                         data=json.dumps({'Name': self.ALIAS_NAME, 'FunctionVersion': '1',
                                          'Description': self.ALIAS_NAME}))

        response = self.client.get('{0}/functions/{1}/aliases'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME))
        result = json.loads(response.get_data())
        for alias in result['Aliases']:
            alias.pop('RevisionId', None)  # we need to remove this, since this is random, so we cannot know its value
        expected_result = {'Aliases': [
            {
                'AliasArn': lambda_api.func_arn(self.FUNCTION_NAME) + ':' + self.ALIAS_NAME,
                'FunctionVersion': '1',
                'Name': self.ALIAS_NAME,
                'Description': self.ALIAS_NAME
            },
            {
                'AliasArn': lambda_api.func_arn(self.FUNCTION_NAME) + ':' + self.ALIAS2_NAME,
                'FunctionVersion': '$LATEST',
                'Name': self.ALIAS2_NAME,
                'Description': ''
            }
        ]}
        self.assertDictEqual(expected_result, result)

    def test_list_non_existant_function_aliases_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.list_aliases(self.FUNCTION_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                             result['message'])

    def test_get_container_name(self):
        executor = lambda_executors.EXECUTOR_CONTAINERS_REUSE
        name = executor.get_container_name('arn:aws:lambda:us-east-1:00000000:function:my_function_name')
        self.assertEqual(name, 'localstack_lambda_arn_aws_lambda_us-east-1_00000000_function_my_function_name')

    def test_put_concurrency(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            # note: PutFunctionConcurrency is mounted at: /2017-10-31
            # NOT lambda_api.PATH_ROOT
            # https://docs.aws.amazon.com/lambda/latest/dg/API_PutFunctionConcurrency.html
            concurrency_data = {'ReservedConcurrentExecutions': 10}
            response = self.client.put('/2017-10-31/functions/{0}/concurrency'.format(self.FUNCTION_NAME),
                                       data=json.dumps(concurrency_data))

            result = json.loads(response.get_data())
            self.assertDictEqual(concurrency_data, result)

    def test_concurrency_get_function(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            # note: PutFunctionConcurrency is mounted at: /2017-10-31
            # NOT lambda_api.PATH_ROOT
            # https://docs.aws.amazon.com/lambda/latest/dg/API_PutFunctionConcurrency.html
            concurrency_data = {'ReservedConcurrentExecutions': 10}
            self.client.put('/2017-10-31/functions/{0}/concurrency'.format(self.FUNCTION_NAME),
                            data=json.dumps(concurrency_data))

            response = self.client.get('{0}/functions/{1}'.format(lambda_api.PATH_ROOT, self.FUNCTION_NAME))

            result = json.loads(response.get_data())
            self.assertTrue('Concurrency' in result)
            self.assertDictEqual(concurrency_data, result['Concurrency'])

    def test_list_tags(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME, self.TAGS)
            arn = lambda_api.func_arn(self.FUNCTION_NAME)
            response = self.client.get('{0}/tags/{1}'.format(lambda_api.PATH_ROOT, arn))
            result = json.loads(response.get_data())
            self.assertTrue('Tags' in result)
            self.assertDictEqual(self.TAGS, result['Tags'])

    def test_tag_resource(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            arn = lambda_api.func_arn(self.FUNCTION_NAME)
            response = self.client.get('{0}/tags/{1}'.format(lambda_api.PATH_ROOT, arn))
            result = json.loads(response.get_data())
            self.assertTrue('Tags' in result)
            self.assertDictEqual({}, result['Tags'])

            self.client.post('{0}/tags/{1}'.format(lambda_api.PATH_ROOT, arn), data=json.dumps({'Tags': self.TAGS}))
            response = self.client.get('{0}/tags/{1}'.format(lambda_api.PATH_ROOT, arn))
            result = json.loads(response.get_data())
            self.assertTrue('Tags' in result)
            self.assertDictEqual(self.TAGS, result['Tags'])

    def test_tag_non_existent_function_returns_error(self):
        with self.app.test_request_context():
            arn = lambda_api.func_arn('non-existent-function')
            response = self.client.post(
                '{0}/tags/{1}'.format(lambda_api.PATH_ROOT, arn),
                data=json.dumps({'Tags': self.TAGS}))
            result = json.loads(response.get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(
                self.RESOURCENOTFOUND_MESSAGE % arn,
                result['message'])

    def test_untag_resource(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME, tags=self.TAGS)
            arn = lambda_api.func_arn(self.FUNCTION_NAME)
            response = self.client.get('{0}/tags/{1}'.format(lambda_api.PATH_ROOT, arn))
            result = json.loads(response.get_data())
            self.assertTrue('Tags' in result)
            self.assertDictEqual(self.TAGS, result['Tags'])

            self.client.delete('{0}/tags/{1}'.format(lambda_api.PATH_ROOT, arn), query_string={'tagKeys': 'env'})
            response = self.client.get('{0}/tags/{1}'.format(lambda_api.PATH_ROOT, arn))
            result = json.loads(response.get_data())
            self.assertTrue('Tags' in result)
            self.assertDictEqual({'hello': 'world'}, result['Tags'])

    def test_java_options_empty_return_empty_value(self):
        lambda_executors.config.LAMBDA_JAVA_OPTS = ''
        result = lambda_executors.Util.get_java_opts()
        self.assertFalse(result)

    def test_java_options_with_only_memory_options(self):
        expected = '-Xmx512M'
        result = self.prepare_java_opts(expected)
        self.assertEqual(expected, result)

    def test_java_options_with_memory_options_and_agentlib_option(self):
        expected = '.*transport=dt_socket,server=y,suspend=y,address=[0-9]+'
        result = self.prepare_java_opts('-Xmx512M -agentlib:jdwp=transport=dt_socket,server=y'
                                      ',suspend=y,address=_debug_port_')
        self.assertTrue(re.match(expected, result))

    def prepare_java_opts(self, java_opts):
        lambda_executors.config.LAMBDA_JAVA_OPTS = java_opts
        result = lambda_executors.Util.get_java_opts()
        return result

    def test_get_java_lib_folder_classpath(self):
        jar_file = os.path.join(new_tmp_dir(), 'foo.jar')
        save_file(jar_file, '')
        self.assertEquals('.:foo.jar', lambda_executors.Util.get_java_classpath(jar_file))

    def test_get_java_lib_folder_classpath_no_directories(self):
        base_dir = new_tmp_dir()
        jar_file = os.path.join(base_dir, 'foo.jar')
        save_file(jar_file, '')
        lib_file = os.path.join(base_dir, 'lib', 'lib.jar')
        mkdir(os.path.dirname(lib_file))
        save_file(lib_file, '')
        self.assertEquals('.:foo.jar:lib/lib.jar', lambda_executors.Util.get_java_classpath(jar_file))

    def test_get_java_lib_folder_classpath_archive_is_None(self):
        self.assertRaises(TypeError, lambda_executors.Util.get_java_classpath, None)

    def _create_function(self, function_name, tags={}):
        arn = lambda_api.func_arn(function_name)
        lambda_api.arn_to_lambda[arn] = LambdaFunction(arn)
        lambda_api.arn_to_lambda[arn].versions = {
            '$LATEST': {'CodeSize': self.CODE_SIZE, 'CodeSha256': self.CODE_SHA_256, 'RevisionId': self.REVISION_ID}
        }
        lambda_api.arn_to_lambda[arn].handler = self.HANDLER
        lambda_api.arn_to_lambda[arn].runtime = self.RUNTIME
        lambda_api.arn_to_lambda[arn].timeout = self.TIMEOUT
        lambda_api.arn_to_lambda[arn].tags = tags
        lambda_api.arn_to_lambda[arn].envvars = {}
        lambda_api.arn_to_lambda[arn].last_modified = self.LAST_MODIFIED
        lambda_api.arn_to_lambda[arn].role = self.ROLE
        lambda_api.arn_to_lambda[arn].memory_size = self.MEMORY_SIZE
