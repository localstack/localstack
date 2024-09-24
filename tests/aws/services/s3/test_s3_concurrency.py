import logging
import random
import threading

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)


class TestParallelBucketCreation:
    @markers.aws.only_localstack
    def test_parallel_bucket_creation(self, aws_client_factory, cleanups):
        num_threads = 10
        create_barrier = threading.Barrier(num_threads)
        errored = False

        def _create_bucket(runner: int):
            nonlocal errored
            bucket_name = f"bucket-{short_uid()}"
            s3_client = aws_client_factory(
                region_name="us-east-1", aws_access_key_id=f"{runner:012d}"
            ).s3
            cleanups.append(lambda: s3_client.delete_bucket(Bucket=bucket_name))
            create_barrier.wait()
            try:
                s3_client.create_bucket(Bucket=bucket_name)
                s3_client.create_bucket(Bucket=bucket_name)
            except Exception:
                LOG.exception("Create bucket failed")
                errored = True

        thread_list = []
        for i in range(1, num_threads + 1):
            thread = threading.Thread(target=_create_bucket, args=[i])
            thread.start()
            thread_list.append(thread)

        for thread in thread_list:
            thread.join()

        assert not errored

    @markers.aws.only_localstack
    def test_parallel_object_creation_and_listing(self, aws_client, s3_bucket):
        num_threads = 20
        create_barrier = threading.Barrier(num_threads)
        errored = False

        def _create_or_list(runner: int):
            nonlocal errored
            create_barrier.wait()
            try:
                if runner % 2:
                    aws_client.s3.list_objects_v2(Bucket=s3_bucket)
                else:
                    aws_client.s3.put_object(
                        Bucket=s3_bucket, Key=f"random-key-{runner}", Body="random"
                    )
            except Exception:
                LOG.exception("Listing objects failed")
                errored = True

        thread_list = []
        for i in range(1, num_threads + 1):
            thread = threading.Thread(target=_create_or_list, args=[i])
            thread.start()
            thread_list.append(thread)

        for thread in thread_list:
            thread.join()

        assert not errored

    @markers.aws.only_localstack
    def test_parallel_object_creation_and_read(self, aws_client, s3_bucket):
        num_threads = 100
        create_barrier = threading.Barrier(num_threads)
        errored = False
        aws_client.s3.put_object(Bucket=s3_bucket, Key="random-key", Body="random")

        def _create_or_read(runner: int):
            nonlocal errored
            create_barrier.wait()
            try:
                if random.choice((1, 2)) == 1:
                    aws_client.s3.get_object(Bucket=s3_bucket, Key="random-key")
                else:
                    aws_client.s3.put_object(Bucket=s3_bucket, Key="random-key", Body="random")
            except Exception:
                LOG.exception("Put/get objects failed")
                errored = True

        thread_list = []
        for i in range(1, num_threads + 1):
            thread = threading.Thread(target=_create_or_read, args=[i])
            thread.start()
            thread_list.append(thread)

        for thread in thread_list:
            thread.join()

        assert not errored

    @markers.aws.only_localstack
    def test_parallel_object_read_range(self, aws_client, s3_bucket):
        num_threads = 100
        create_barrier = threading.Barrier(num_threads)
        errored = False
        body = "random" * 100
        len_body = len(body)
        aws_client.s3.put_object(Bucket=s3_bucket, Key="random-key", Body=body)

        def _create_or_read(runner: int):
            nonlocal errored
            create_barrier.wait()
            try:
                start = random.randrange(0, len_body)
                end = random.randrange(start, len_body)

                aws_client.s3.get_object(
                    Bucket=s3_bucket, Key="random-key", Range=f"bytes={start}-{end}"
                )

            except Exception:
                LOG.exception("get ranged objects failed")
                errored = True

        thread_list = []
        for i in range(1, num_threads + 1):
            thread = threading.Thread(target=_create_or_read, args=[i])
            thread.start()
            thread_list.append(thread)

        for thread in thread_list:
            thread.join()

        assert not errored
