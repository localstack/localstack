import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

export const handler = async (event, context) => {
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
            signatureVersion: 'v4', // Required for the presigned URL functionality with extra headers
            credentials: CREDENTIALS,
        });
    } else {
        s3 = new S3Client({ signatureVersion: 'v4' });
    }

    const url = await getSignedUrl(
        s3,
        new PutObjectCommand({
            Bucket: BUCKET_NAME,
            Key: 'key-for-signed-headers-in-qs',
            ServerSideEncryption: 'AES256', // Adds 'X-Amz-Server-Side-Encryption'
            ContentMD5: bodyMd5AsBase64
        }),
        {
            expiresIn: 3600,
        }
    );
    return {
        statusCode: 200,
        body: JSON.stringify(url)
    };
}
