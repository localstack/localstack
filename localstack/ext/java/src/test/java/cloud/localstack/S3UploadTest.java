package cloud.localstack;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
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

	/**
	 * Test based on https://github.com/localstack/localstack/issues/359
	 */
	@Test
	public void testTrival() throws Exception  {
		testUpload("{}"); // Some JSON content, just an example
	}

	/**
	 * Tests greater than 128k uploads
	 * @throws Exception
	 */
	@Test
	public void testGreaterThan128k() throws Exception  {
		testUpload(String.join("", Collections.nCopies(13108, "abcdefghij"))); // Just slightly more than 2^17 bytes
	}

	/**
	 * Tests less than 128k uploads
	 * @throws Exception
	 */
	@Test
	public void testLessThan128k() throws Exception  {
		testUpload(String.join("", Collections.nCopies(13107, "abcdefghij"))); // Just slightly less than 2^17 bytes
    }

	/**
	 * Tests upload of empty file. This is an operation that hadoop's S3AFilesystem executes to create "directories"
	 * in S3.
	 *
	 * This test is currently failing because the S3 server doesn't properly calculate the MD5 of null string.
	 */
	@Test
	public void testZeroLengthUpload() {
		AmazonS3 client = TestUtils.getClientS3();

		String bucketName = UUID.randomUUID().toString();
		String keyName = UUID.randomUUID().toString();
		client.createBucket(bucketName);

		final ObjectMetadata objectMetadata = new ObjectMetadata();
		final InputStream inputStream = new ByteArrayInputStream(new byte[0]);
		objectMetadata.setContentLength(0L);
		PutObjectRequest putObjectRequest = new PutObjectRequest(bucketName,
																 keyName,
																 inputStream,
																 objectMetadata);
		client.putObject(putObjectRequest);
	}

	private void testUpload(final String dataString) throws Exception {
		AmazonS3 client = TestUtils.getClientS3();

		String bucketName = UUID.randomUUID().toString();
		String keyName = UUID.randomUUID().toString();
		client.createBucket(bucketName);

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
