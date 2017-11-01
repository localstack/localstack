import unittest

from backports.tempfile import TemporaryDirectory
from nose.tools import assert_true, assert_false, assert_equal

from localstack.utils import persistence


class TestPersistence(unittest.TestCase):
    temp_dir = None

    # just in case tests run in parallel, we want to only
    # create the temp_dir once
    @classmethod
    def setup_class(cls):
        cls.temp_dir = TemporaryDirectory()
        persistence.DATA_DIR = cls.temp_dir.name

    @classmethod
    def teardown_class(cls):
        cls.temp_dir.cleanup()
        persistence.DATA_DIR = None

    def test_should_record(self):
        assert_true(persistence.should_record('s3', 'PUT', None, None, None))
        assert_true(persistence.should_record('s3', 'POST', None, None, None))
        assert_true(persistence.should_record('s3', 'DELETE', None, None, None))

        assert_false(persistence.should_record('s3', 'GET', None, None, None))
        assert_false(persistence.should_record('s3', 'FAKE_METHOD', None, None, None))
        assert_false(persistence.should_record('not_s3', 'PUT', None, None, None))
        assert_false(persistence.should_record(None, None, None, None, None))

    def test_record(self):
        persistence.record(
            's3', 'POST', 'path',
            {'data': 'data_val'},
            {'header1': 'header_val'},
        )

    def test_get_file_path(self):
        assert_equal(
            persistence.get_file_path('s3', create=True),
            persistence.DATA_DIR + '/s3_api_calls.json'
        )

        assert_false(
            persistence.get_file_path('invalid_api', create=False)
        )
