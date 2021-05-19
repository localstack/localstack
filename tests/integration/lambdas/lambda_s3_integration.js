exports.handler = async (event, context, callback) => {
    const {
        S3Client,
        PutObjectCommand,
    } = require("@aws-sdk/client-s3");
    const {
        getSignedUrl
    } = require('@aws-sdk/s3-request-presigner');

    const CREDENTIALS = {
        secretAccessKey: 'test',
        accessKeyId: 'test',
    };

    const ENDPOINT = {
        path: '',
        hostname: 's3.localhost.localstack.cloud:4566',
        protocol: 'http',
    };

    const BUCKET_NAME = process.env.AWS_LAMBDA_FUNCTION_NAME;

    const s3 = new S3Client({
        endpoint: ENDPOINT,
        region: 'us-east-1',
        credentials: CREDENTIALS,
    });

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
