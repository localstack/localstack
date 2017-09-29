package cloud.localstack;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.entity.ContentType;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;

/**
 * Test S3 uploads to LocalStack
 */
@RunWith(LocalstackTestRunner.class)
public class S3UploadTest {

	@Test
	public void testUpload() throws Exception {
		/*
		 * Test based on https://github.com/localstack/localstack/issues/359
		 */

		AmazonS3 client = TestUtils.getClientS3();

		String bucketName = UUID.randomUUID().toString();
		String keyName = UUID.randomUUID().toString();
		client.createBucket(bucketName);

		String dataString = "{}"; // Some JSON content, just an example
		byte[] dataBytes = dataString.getBytes(StandardCharsets.UTF_8);

		ObjectMetadata metaData = new ObjectMetadata();
		metaData.setContentType(ContentType.APPLICATION_JSON.toString());
		metaData.setContentEncoding(StandardCharsets.UTF_8.name());
		metaData.setContentLength(dataBytes.length);

		byte[] resultByte = DigestUtils.md5(dataBytes);
		String streamMD5 = new String(Base64.encodeBase64(resultByte));
		metaData.setContentMD5(streamMD5);

		PutObjectRequest putObjectRequest = new PutObjectRequest(bucketName, keyName,
				new ByteArrayInputStream(dataBytes), metaData);
		client.putObject(putObjectRequest);

		S3Object object = client.getObject(bucketName, keyName);
		String returnedContent = IOUtils.toString(object.getObjectContent(), "utf-8");
		assertEquals(streamMD5, object.getObjectMetadata().getContentMD5());
		assertEquals(returnedContent,  dataString);

		client.deleteObject(bucketName, keyName);
		client.deleteBucket(bucketName);
	}

}
