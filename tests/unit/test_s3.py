import unittest
from localstack.services.s3 import s3_listener


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

        key1, url1 = s3_listener.find_multipart_redirect_url(data1, headers)

        self.assertEqual(key1, 'uploads/20170826T181315.679087009Z/upload/pixel.png')
        self.assertEqual(url1, 'http://127.0.0.1:5000/?id=20170826T181315.679087009Z')

        key2, url2 = s3_listener.find_multipart_redirect_url(data2, headers)

        self.assertEqual(key2, 'uploads/20170826T181315.679087009Z/upload/pixel.png')
        self.assertIsNone(url2, 'Should not get a redirect URL without success_action_redirect')

        key3, url3 = s3_listener.find_multipart_redirect_url(data3, headers)

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

        expanded1 = s3_listener.expand_multipart_filename(data1, headers)
        self.assertIsNot(expanded1, data1, 'Should have changed content of data with filename to interpolate')
        self.assertIn(b'uploads/20170826T181315.679087009Z/upload/pixel.png', expanded1,
            'Should see the interpolated filename')

        expanded2 = s3_listener.expand_multipart_filename(data2, headers)
        self.assertIs(expanded2, data2, 'Should not have changed content of data with no filename to interpolate')

        expanded3 = s3_listener.expand_multipart_filename(data3, headers)
        self.assertIsNot(expanded3, data3, 'Should have changed content of string data with filename to interpolate')
        self.assertIn(b'uploads/20170826T181315.679087009Z/upload/pixel.txt', expanded3,
            'Should see the interpolated filename')
