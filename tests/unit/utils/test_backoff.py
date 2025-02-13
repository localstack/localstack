import time
import unittest

from localstack.utils.backoff import ExponentialBackoff


class TestExponentialBackoff(unittest.TestCase):
    def test_next_backoff(self):
        initial_expected_backoff = 0.5  # 500ms
        multiplication_factor = 1.5  # increase by x1.5 each iteration

        boff = ExponentialBackoff(randomization_factor=0)  # no jitter for deterministic testing

        backoff_duration_iter_1 = boff.next_backoff()
        self.assertEqual(backoff_duration_iter_1, initial_expected_backoff)

        backoff_duration_iter_2 = boff.next_backoff()
        self.assertEqual(backoff_duration_iter_2, initial_expected_backoff * multiplication_factor)

        backoff_duration_iter_3 = boff.next_backoff()
        self.assertEqual(
            backoff_duration_iter_3, initial_expected_backoff * multiplication_factor**2
        )

    def test_backoff_retry_limit(self):
        initial_expected_backoff = 0.5
        max_retries_before_stop = 1

        boff = ExponentialBackoff(randomization_factor=0, max_retries=max_retries_before_stop)

        self.assertEqual(boff.next_backoff(), initial_expected_backoff)

        # max_retries exceeded, only 0 should be returned until reset() called
        self.assertEqual(boff.next_backoff(), 0)
        self.assertEqual(boff.next_backoff(), 0)

        # reset backoff
        boff.reset()

        self.assertEqual(boff.next_backoff(), initial_expected_backoff)
        self.assertEqual(boff.next_backoff(), 0)

    def test_backoff_retry_limit_disable_retries(self):
        boff = ExponentialBackoff(randomization_factor=0, max_retries=0)

        # zero max_retries means backoff will always fail
        self.assertEqual(boff.next_backoff(), 0)

        # reset backoff
        boff.reset()

        # reset has no effect since backoff is disabled
        self.assertEqual(boff.next_backoff(), 0)

    def test_backoff_time_elapsed_limit(self):
        initial_expected_backoff = 0.5
        multiplication_factor = 1.5  # increase by x1.5 each iteration

        max_time_elapsed_s_before_stop = 1.0

        boff = ExponentialBackoff(
            randomization_factor=0, max_time_elapsed=max_time_elapsed_s_before_stop
        )
        self.assertEqual(boff.next_backoff(), initial_expected_backoff)
        self.assertEqual(boff.next_backoff(), initial_expected_backoff * multiplication_factor)

        # sleep for 1s
        time.sleep(1)

        # max_time_elapsed exceeded, only 0 should be returned until reset() called
        self.assertEqual(boff.next_backoff(), 0)
        self.assertEqual(boff.next_backoff(), 0)

        # reset backoff
        boff.reset()

        self.assertEqual(boff.next_backoff(), initial_expected_backoff)
        self.assertEqual(boff.next_backoff(), initial_expected_backoff * multiplication_factor)

    def test_backoff_elapsed_limit_reached_before_retry_limit(self):
        initial_expected_backoff = 0.5
        multiplication_factor = 1.5

        max_retries_before_stop = 4
        max_time_elasped_s_before_stop = 2.0

        boff = ExponentialBackoff(
            randomization_factor=0,
            max_retries=max_retries_before_stop,
            max_time_elapsed=max_time_elasped_s_before_stop,
        )

        total_duration = 0
        for retry in range(2):
            backoff_duration = boff.next_backoff()
            expected_duration = initial_expected_backoff * multiplication_factor**retry
            self.assertEqual(backoff_duration, expected_duration)

            # Sleep for backoff
            time.sleep(backoff_duration)
            total_duration += backoff_duration

        self.assertLess(total_duration, max_time_elasped_s_before_stop)

        # sleep for remainder of wait time...
        time.sleep(max_time_elasped_s_before_stop - total_duration)

        # max_retries exceeded, only 0 should be returned until reset() called
        self.assertEqual(boff.next_backoff(), 0)

    def test_backoff_retry_limit_reached_before_elapsed_limit(self):
        initial_expected_backoff = 0.5
        multiplication_factor = 1.5

        max_retries_before_stop = 3
        max_time_elasped_s_before_stop = 3.0

        boff = ExponentialBackoff(
            randomization_factor=0,
            max_retries=max_retries_before_stop,
            max_time_elapsed=max_time_elasped_s_before_stop,
        )

        total_duration = 0
        for retry in range(max_retries_before_stop):
            backoff_duration = boff.next_backoff()
            expected_duration = initial_expected_backoff * multiplication_factor**retry
            self.assertEqual(backoff_duration, expected_duration)

            # Sleep for backoff
            time.sleep(backoff_duration)
            total_duration += backoff_duration

        self.assertLess(total_duration, max_time_elasped_s_before_stop)

        # max_retries exceeded, only 0 should be returned until reset() called
        self.assertEqual(boff.next_backoff(), 0)
