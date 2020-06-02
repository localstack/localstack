import unittest
from localstack.services.edge import is_s3_form_data


class EdgeServiceTest(unittest.TestCase):

    def test_data_contains_key_equal_is_true(self):
        data_bytes = b'AWSAccessKeyId=someId&policy=somePolicy&key=someKey&signature=someSig'
        self.assertEqual(is_s3_form_data(data_bytes), True)

    def test_s3_form_data_is_true(self):
        data_bytes = b"""--28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="Content-Type"

        text/plain
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="key"

        log.txt
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="AWSAccessKeyId"

        AKIAIG7AH67ANH3GAWPQ
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="policy"

        somePolicy
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="signature"

        hTahNRfuCxL5HEKdhXxJPwvC6IQ=
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="file"; filename="file"

        Hello World!
        --28f72589b2be0c9de84386b52c615990--
        """
        self.assertEqual(is_s3_form_data(data_bytes), True)

    def test_other_query_params_is_false(self):
        data_bytes = b'AWSAccessKeyId=someId&policy=somePolicy&param=value&signature=someSig'
        self.assertEqual(is_s3_form_data(data_bytes), False)

    def test_other_form_data_is_false(self):
        data_bytes = b"""--28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="AWSAccessKeyId"

        AKIAIG7AH67ANH3GAWPQ
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="policy"

        somePolicy
        --28f72589b2be0c9de84386b52c615990
        Content-Disposition: form-data; name="signature"

        hTahNRfuCxL5HEKdhXxJPwvC6IQ=
        --28f72589b2be0c9de84386b52c615990--
        """
        self.assertEqual(is_s3_form_data(data_bytes), False)
