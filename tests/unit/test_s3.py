import unittest
from localstack.services.s3 import s3_listener, multipart_content
from requests.models import CaseInsensitiveDict


class S3ListenerTest (unittest.TestCase):

    def test_expand_redirect_url(self):
        url1 = s3_listener.expand_redirect_url('http://example.org', 'K', 'B')
        self.assertEqual(url1, 'http://example.org?key=K&bucket=B')

        url2 = s3_listener.expand_redirect_url('http://example.org/?id=I', 'K', 'B')
        self.assertEqual(url2, 'http://example.org/?id=I&key=K&bucket=B')

    def test_find_multipart_redirect_url(self):
        headers = {'Host': '10.0.1.19:4572', 'User-Agent': 'curl/7.51.0',
            'Accept': '*/*', 'Content-Length': '992', 'Expect': '100-continue',
            'Content-Type': 'multipart/form-data; boundary=------------------------3c48c744237517ac'}

        data1 = (b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
                 b'uploads/20170826T181315.679087009Z/upload/pixel.png\r\n--------------------------3c48c744237517ac'
                 b'\r\nContent-Disposition: form-data; name="success_action_redirect"\r\n\r\nhttp://127.0.0.1:5000/'
                 b'?id=20170826T181315.679087009Z\r\n--------------------------3c48c744237517ac--\r\n')

        data2 = (b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
                 b'uploads/20170826T181315.679087009Z/upload/pixel.png\r\n--------------------------3c48c744237517ac'
                 b'--\r\n')

        data3 = (b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="success_action_'
                 b'redirect"\r\n\r\nhttp://127.0.0.1:5000/?id=20170826T181315.679087009Z\r\n--------------------------'
                 b'3c48c744237517ac--\r\n')

        key1, url1 = multipart_content.find_multipart_redirect_url(data1, headers)

        self.assertEqual(key1, 'uploads/20170826T181315.679087009Z/upload/pixel.png')
        self.assertEqual(url1, 'http://127.0.0.1:5000/?id=20170826T181315.679087009Z')

        key2, url2 = multipart_content.find_multipart_redirect_url(data2, headers)

        self.assertEqual(key2, 'uploads/20170826T181315.679087009Z/upload/pixel.png')
        self.assertIsNone(url2, 'Should not get a redirect URL without success_action_redirect')

        key3, url3 = multipart_content.find_multipart_redirect_url(data3, headers)

        self.assertIsNone(key3, 'Should not get a key without provided key')
        self.assertIsNone(url3, 'Should not get a redirect URL without provided key')

    def test_expand_multipart_filename(self):
        headers = {'Host': '10.0.1.19:4572', 'User-Agent': 'curl/7.51.0',
            'Accept': '*/*', 'Content-Length': '992', 'Expect': '100-continue',
            'Content-Type': 'multipart/form-data; boundary=------------------------3c48c744237517ac'}

        data1 = (b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
                 b'uploads/20170826T181315.679087009Z/upload/${filename}\r\n--------------------------3c48c744237517ac'
                 b'\r\nContent-Disposition: form-data; name="AWSAccessKeyId"\r\n\r\nWHAT\r\n--------------------------'
                 b'3c48c744237517ac\r\nContent-Disposition: form-data; name="policy"\r\n\r\nNO\r\n--------------------'
                 b'------3c48c744237517ac\r\nContent-Disposition: form-data; name="signature"\r\n\r\nYUP\r\n----------'
                 b'----------------3c48c744237517ac\r\nContent-Disposition: form-data; name="acl"\r\n\r\nprivate\r\n--'
                 b'------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="success_action_re'
                 b'direct"\r\n\r\nhttp://127.0.0.1:5000/\r\n--------------------------3c48c744237517ac\r\nContent-Disp'
                 b'osition: form-data; name="file"; filename="pixel.png"\r\nContent-Type: application/octet-stream\r\n'
                 b'\r\n\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15'
                 b'\xc4\x89\x00\x00\x00\x19tEXtSoftware\x00Adobe ImageReadyq\xc9e<\x00\x00\x00\x0eIDATx\xdabb\x00\x02'
                 b'\x80\x00\x03\x00\x00\x0f\x00\x03`|\xce\xe9\x00\x00\x00\x00IEND\xaeB`\x82\r\n-----------------------'
                 b'---3c48c744237517ac--\r\n')

        data2 = (b'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
                 b'uploads/20170826T181315.679087009Z/upload/pixel.png\r\n--------------------------3c48c744237517ac'
                 b'\r\nContent-Disposition: form-data; name="AWSAccessKeyId"\r\n\r\nWHAT\r\n--------------------------'
                 b'3c48c744237517ac\r\nContent-Disposition: form-data; name="policy"\r\n\r\nNO\r\n--------------------'
                 b'------3c48c744237517ac\r\nContent-Disposition: form-data; name="signature"\r\n\r\nYUP\r\n----------'
                 b'----------------3c48c744237517ac\r\nContent-Disposition: form-data; name="acl"\r\n\r\nprivate\r\n--'
                 b'------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="success_action_re'
                 b'direct"\r\n\r\nhttp://127.0.0.1:5000/\r\n--------------------------3c48c744237517ac\r\nContent-Disp'
                 b'osition: form-data; name="file"; filename="pixel.png"\r\nContent-Type: application/octet-stream\r\n'
                 b'\r\n\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15'
                 b'\xc4\x89\x00\x00\x00\x19tEXtSoftware\x00Adobe ImageReadyq\xc9e<\x00\x00\x00\x0eIDATx\xdabb\x00\x02'
                 b'\x80\x00\x03\x00\x00\x0f\x00\x03`|\xce\xe9\x00\x00\x00\x00IEND\xaeB`\x82\r\n-----------------------'
                 b'---3c48c744237517ac--\r\n')

        data3 = (u'--------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="key"\r\n\r\n'
                 u'uploads/20170826T181315.679087009Z/upload/${filename}\r\n--------------------------3c48c744237517ac'
                 u'\r\nContent-Disposition: form-data; name="AWSAccessKeyId"\r\n\r\nWHAT\r\n--------------------------'
                 u'3c48c744237517ac\r\nContent-Disposition: form-data; name="policy"\r\n\r\nNO\r\n--------------------'
                 u'------3c48c744237517ac\r\nContent-Disposition: form-data; name="signature"\r\n\r\nYUP\r\n----------'
                 u'----------------3c48c744237517ac\r\nContent-Disposition: form-data; name="acl"\r\n\r\nprivate\r\n--'
                 u'------------------------3c48c744237517ac\r\nContent-Disposition: form-data; name="success_action_re'
                 u'direct"\r\n\r\nhttp://127.0.0.1:5000/\r\n--------------------------3c48c744237517ac\r\nContent-Disp'
                 u'osition: form-data; name="file"; filename="pixel.txt"\r\nContent-Type: text/plain\r\n\r\nHello World'
                 u'\r\n--------------------------3c48c744237517ac--\r\n')

        expanded1 = multipart_content.expand_multipart_filename(data1, headers)
        self.assertIsNot(expanded1, data1, 'Should have changed content of data with filename to interpolate')
        self.assertIn(b'uploads/20170826T181315.679087009Z/upload/pixel.png', expanded1,
            'Should see the interpolated filename')

        expanded2 = multipart_content.expand_multipart_filename(data2, headers)
        self.assertIs(expanded2, data2, 'Should not have changed content of data with no filename to interpolate')

        expanded3 = multipart_content.expand_multipart_filename(data3, headers)
        self.assertIsNot(expanded3, data3, 'Should have changed content of string data with filename to interpolate')
        self.assertIn(b'uploads/20170826T181315.679087009Z/upload/pixel.txt', expanded3,
            'Should see the interpolated filename')

    def test_get_bucket_lifecycle(self):
        bucket_name = 'test-bucket'
        returned_empty_lifecycle = s3_listener.get_lifecycle(bucket_name)
        self.assertRegexpMatches(returned_empty_lifecycle._content, r'LifecycleConfiguration')

    def test_get_bucket_name(self):
        bucket_name = 'test-bucket'
        s3_key = '/some-folder/some-key.txt'

        hosts = ['s3-ap-northeast-1.amazonaws.com',
                 's3-ap-northeast-2.amazonaws.com',
                 's3-ap-south-1.amazonaws.com',
                 's3-ap-southeast-1.amazonaws.com',
                 's3-ap-southeast-2.amazonaws.com',
                 's3-ca-central-1.amazonaws.com',
                 's3-eu-central-1.amazonaws.com',
                 's3-eu-west-1.amazonaws.com',
                 's3-eu-west-2.amazonaws.com',
                 's3-eu-west-3.amazonaws.com',
                 's3-external-1.amazonaws.com',
                 's3-sa-east-1.amazonaws.com',
                 's3-us-east-2.amazonaws.com',
                 's3-us-west-1.amazonaws.com',
                 's3-us-west-2.amazonaws.com',
                 's3.amazonaws.com',
                 's3.ap-northeast-1.amazonaws.com',
                 's3.ap-northeast-2.amazonaws.com',
                 's3.ap-south-1.amazonaws.com',
                 's3.ap-southeast-1.amazonaws.com',
                 's3.ap-southeast-2.amazonaws.com',
                 's3.ca-central-1.amazonaws.com',
                 's3.cn-north-1.amazonaws.com.cn',
                 's3.cn-northwest-1.amazonaws.com.cn',
                 's3.dualstack.ap-northeast-1.amazonaws.com',
                 's3.dualstack.ap-northeast-2.amazonaws.com',
                 's3.dualstack.ap-south-1.amazonaws.com',
                 's3.dualstack.ap-southeast-1.amazonaws.com',
                 's3.dualstack.ap-southeast-2.amazonaws.com',
                 's3.dualstack.ca-central-1.amazonaws.com',
                 's3.dualstack.eu-central-1.amazonaws.com',
                 's3.dualstack.eu-west-1.amazonaws.com',
                 's3.dualstack.eu-west-2.amazonaws.com',
                 's3.dualstack.eu-west-3.amazonaws.com',
                 's3.dualstack.sa-east-1.amazonaws.com',
                 's3.dualstack.us-east-1.amazonaws.com',
                 's3.dualstack.us-east-2.amazonaws.com',
                 's3.dualstack.us-west-1.amazonaws.com',
                 's3.dualstack.us-west-2.amazonaws.com',
                 's3.eu-central-1.amazonaws.com',
                 's3.eu-west-1.amazonaws.com',
                 's3.eu-west-2.amazonaws.com',
                 's3.eu-west-3.amazonaws.com',
                 's3.sa-east-1.amazonaws.com',
                 's3.us-east-1.amazonaws.com',
                 's3.us-east-2.amazonaws.com',
                 's3.us-west-1.amazonaws.com',
                 's3.us-west-2.amazonaws.com']

        # test all available hosts with the bucket_name in the path
        bucket_path = '/{}/{}'.format(bucket_name, s3_key)
        for host in hosts:
            headers = CaseInsensitiveDict({'Host': hosts[0]})
            returned_bucket_name = s3_listener.get_bucket_name(bucket_path, headers)
            self.assertEqual(returned_bucket_name, bucket_name, 'Should match when bucket_name is in path')

        # test all available hosts with the bucket_name in the host and the path is only the s3_key
        for host in hosts:
            headers = CaseInsensitiveDict({'Host': '{}.{}'.format(bucket_name, host)})
            returned_bucket_name = s3_listener.get_bucket_name(s3_key, headers)
            self.assertEqual(returned_bucket_name, bucket_name, 'Should match when bucket_name is in the host')

    def test_event_type_matching(self):
        match = s3_listener.event_type_matches
        self.assertTrue(match(['s3:ObjectCreated:*'], 'ObjectCreated', 'Put'))
        self.assertTrue(match(['s3:ObjectCreated:*'], 'ObjectCreated', 'Post'))
        self.assertTrue(match(['s3:ObjectCreated:Post'], 'ObjectCreated', 'Post'))
        self.assertTrue(match(['s3:ObjectDeleted:*'], 'ObjectDeleted', 'Delete'))
        self.assertFalse(match(['s3:ObjectCreated:Post'], 'ObjectCreated', 'Put'))
        self.assertFalse(match(['s3:ObjectCreated:Post'], 'ObjectDeleted', 'Put'))

    def test_is_query_allowable(self):
        self.assertTrue(s3_listener.ProxyListenerS3.is_query_allowable('POST', 'uploadId'))
        self.assertTrue(s3_listener.ProxyListenerS3.is_query_allowable('POST', ''))
        self.assertTrue(s3_listener.ProxyListenerS3.is_query_allowable('PUT', ''))
        self.assertFalse(s3_listener.ProxyListenerS3.is_query_allowable('POST', 'differentQueryString'))
        # abort multipart upload is a delete with the same query string as a complete multipart upload
        self.assertFalse(s3_listener.ProxyListenerS3.is_query_allowable('DELETE', 'uploadId'))
        self.assertFalse(s3_listener.ProxyListenerS3.is_query_allowable('DELETE', 'differentQueryString'))
        self.assertFalse(s3_listener.ProxyListenerS3.is_query_allowable('PUT', 'uploadId'))
