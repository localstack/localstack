import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

export const handler = async (event, context) => {
    const BUCKET_NAME = process.env.AWS_LAMBDA_FUNCTION_NAME;
    let s3;
    if (process.env.AWS_ENDPOINT_URL) {
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
            Bucket: BUCKET_NAME,
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
