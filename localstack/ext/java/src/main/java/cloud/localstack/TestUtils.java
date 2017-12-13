package cloud.localstack;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClient;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;

import static cloud.localstack.TestUtils.DEFAULT_REGION;
import static cloud.localstack.TestUtils.TEST_CREDENTIALS;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("all")
public class TestUtils {

	public static final String DEFAULT_REGION = "us-east-1";
	public static final String TEST_ACCESS_KEY = "test";
	public static final String TEST_SECRET_KEY = "test";
	public static final AWSCredentials TEST_CREDENTIALS = new BasicAWSCredentials(TEST_ACCESS_KEY, TEST_SECRET_KEY);

	public static void setEnv(String key, String value) {
		Map<String, String> newEnv = new HashMap<String, String>(System.getenv());
		newEnv.put(key, value);
		setEnv(newEnv);
	}

	public static AmazonSQS getClientSQS() {
		return AmazonSQSClientBuilder.standard().
				withEndpointConfiguration(getEndpointConfigurationSQS()).
				withCredentials(getCredentialsProvider()).build();
	}

	public static AWSLambda getClientLambda() {
		return AWSLambdaClientBuilder.standard().
				withEndpointConfiguration(getEndpointConfigurationLambda()).
				withCredentials(getCredentialsProvider()).build();
	}

	public static AmazonS3 getClientS3() {
		AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard().
				withEndpointConfiguration(getEndpointConfigurationS3()).
				withCredentials(getCredentialsProvider());
		builder.setPathStyleAccessEnabled(true);
		return builder.build();
	}

	public static AmazonKinesis getClientKinesis() {
		return AmazonKinesisClientBuilder.standard().
				withEndpointConfiguration(getEndpointConfigurationKinesis()).
				withCredentials(getCredentialsProvider()).build();
	}

	public static AWSCredentialsProvider getCredentialsProvider() {
		return new AWSStaticCredentialsProvider(TEST_CREDENTIALS);
	}

	protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationLambda() {
		return getEndpointConfiguration(LocalstackTestRunner.getEndpointLambda());
	}

	protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationKinesis() {
		return getEndpointConfiguration(LocalstackTestRunner.getEndpointKinesis());
	}

	protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationSQS() {
		return getEndpointConfiguration(LocalstackTestRunner.getEndpointSQS());
	}

	protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationS3() {
		return getEndpointConfiguration(LocalstackTestRunner.getEndpointS3());
	}

	protected static AwsClientBuilder.EndpointConfiguration getEndpointConfiguration(String endpointURL) {
		return new AwsClientBuilder.EndpointConfiguration(endpointURL, DEFAULT_REGION);
	}

	protected static void setEnv(Map<String, String> newEnv) {
		try {
			Class<?> processEnvironmentClass = Class.forName("java.lang.ProcessEnvironment");
			Field theEnvironmentField = processEnvironmentClass.getDeclaredField("theEnvironment");
			theEnvironmentField.setAccessible(true);
			Map<String, String> env = (Map<String, String>) theEnvironmentField.get(null);
			env.putAll(newEnv);
			Field theCaseInsensitiveEnvironmentField = processEnvironmentClass
					.getDeclaredField("theCaseInsensitiveEnvironment");
			theCaseInsensitiveEnvironmentField.setAccessible(true);
			Map<String, String> cienv = (Map<String, String>) theCaseInsensitiveEnvironmentField.get(null);
			cienv.putAll(newEnv);
		} catch (NoSuchFieldException e) {
			try {
				Class[] classes = Collections.class.getDeclaredClasses();
				Map<String, String> env = System.getenv();
				for (Class cl : classes) {
					if ("java.util.Collections$UnmodifiableMap".equals(cl.getName())) {
						Field field = cl.getDeclaredField("m");
						field.setAccessible(true);
						Object obj = field.get(env);
						Map<String, String> map = (Map<String, String>) obj;
						map.clear();
						map.putAll(newEnv);
					}
				}
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}

	public static void disableSslCertChecking() {
		System.setProperty("com.amazonaws.sdk.disableCertChecking", "true");
	}

}
