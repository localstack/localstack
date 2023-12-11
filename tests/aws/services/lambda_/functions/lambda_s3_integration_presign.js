exports.handler = async (event, context, callback) => {
    const {
        S3Client,
        PutObjectCommand,
    } = require("@aws-sdk/client-s3");
    const {
        getSignedUrl
    } = require('@aws-sdk/s3-request-presigner');

    const BUCKET_NAME = process.env.AWS_LAMBDA_FUNCTION_NAME;
    const bodyMd5AsBase64 = '4QrcOUm6Wau+VuBX8g+IPg=='; // body should be '123456'

    let s3;
    if (process.env.AWS_ENDPOINT_URL) {
        const CREDENTIALS = {
            secretAccessKey: process.env.SECRET_KEY,
            accessKeyId: process.env.ACCESS_KEY,
        };

        s3 = new S3Client({
            endpoint: "http://s3.localhost.localstack.cloud:4566",
            region: process.env.AWS_REGION,
            credentials: CREDENTIALS,
        });
    } else {
        s3 = new S3Client()
    }

    const url = await getSignedUrl(
        s3,
        new PutObjectCommand({
            Bucket: BUCKET_NAME,
            Key: 'temp.txt',
            StorageClass: 'STANDARD',
            Metadata: {"foo": "bar-complicated-no-random"},
            ContentMD5: bodyMd5AsBase64
        }),
        {
            expiresIn: 86400
        }
    );
    return {
        statusCode: 200,
        body: JSON.stringify(url)
    };
}
