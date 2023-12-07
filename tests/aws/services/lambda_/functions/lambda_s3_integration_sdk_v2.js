exports.handler = async (event, context, callback) => {
    const AWS = require('aws-sdk');

    const BUCKET_NAME = process.env.AWS_LAMBDA_FUNCTION_NAME;
    const bodyMd5AsBase64 = '4QrcOUm6Wau+VuBX8g+IPg=='; // body should be '123456'

    let s3;
    if (process.env.AWS_ENDPOINT_URL) {
        const CREDENTIALS = {
            secretAccessKey: process.env.SECRET_KEY,
            accessKeyId: process.env.ACCESS_KEY,
        };
        s3 = new AWS.S3({
            endpoint: "http://s3.localhost.localstack.cloud:4566",
            region: process.env.AWS_REGION,
            signatureVersion: 'v4', // Required for the presigned URL functionality with extra headers
            credentials: CREDENTIALS
          });

    } else {
        s3 = new AWS.S3({ signatureVersion: 'v4' })
    }

  const url = s3.getSignedUrl('putObject', {
    Bucket: BUCKET_NAME,
    Key: 'key-for-signed-headers-in-qs',
    Expires: 3600,
    ServerSideEncryption: 'AES256', // Adds 'X-Amz-Server-Side-Encryption' in query string
    ContentMD5: bodyMd5AsBase64             // Adds 'Content-MD5' parameter in query string
    });

    // url: http://localhost:4566/test-bucket-ls-presigned/key-for-signed-headers-in-qs
    //   ?Content-MD5=4QrcOUm6Wau%2BVuBX8g%2BIPg%3D%3D
    //   &X-Amz-Algorithm=AWS4-HMAC-SHA256
    //   &X-Amz-Credential=test%2F20220113%2Fus-east-1%2Fs3%2Faws4_request
    //   &X-Amz-Date=20220113T142952Z
    //   &X-Amz-Expires=3600
    //   &X-Amz-Signature=d219a729f06e37d40a136bb5fec777265b1b34e879f9e338d385b39a3760a14f
    //   &X-Amz-SignedHeaders=content-md5%3Bhost%3Bx-amz-server-side-encryption
    //   &x-amz-server-side-encryption=AES256
    //
    // NOTE X-Amz-SignedHeaders contains `content-md5` and `x-amz-server-side-encryption` keys as well
    return {
        statusCode: 200,
        body: JSON.stringify(url)
    };
}
