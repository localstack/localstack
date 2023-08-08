exports.handler = async (event, context, callback) => {
    const {
        S3Client,
        PutObjectCommand,
    } = require("@aws-sdk/client-s3");
    const {
        getSignedUrl
    } = require('@aws-sdk/s3-request-presigner');

    const BUCKET_NAME = process.env.AWS_LAMBDA_FUNCTION_NAME;
    let s3;
    if (process.env.LOCALSTACK_HOSTNAME) {
        const CREDENTIALS = {
            secretAccessKey: 'test',
            accessKeyId: 'test',
        };

        s3 = new S3Client({
            endpoint: "http://s3.localhost.localstack.cloud:4566",
            region: 'us-east-1',
            credentials: CREDENTIALS,
        });
    } else {
        s3 = new S3Client()
    }

    const url = await getSignedUrl(
        s3,
        new PutObjectCommand({
            Bucket: process.env.AWS_LAMBDA_FUNCTION_NAME,
            Key: 'key.png',
            ContentType: 'image/png'
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
