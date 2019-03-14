package cloud.localstack;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.client.builder.ExecutorFactory;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisAsync;
import com.amazonaws.services.kinesis.AmazonKinesisAsyncClientBuilder;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaAsync;
import com.amazonaws.services.lambda.AWSLambdaAsyncClientBuilder;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSAsync;
import com.amazonaws.services.sns.AmazonSNSAsyncClientBuilder;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sqs.*;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.channels.FileChannel;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

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

    public static AmazonSQSAsync getClientSQSAsync() {
        return AmazonSQSAsyncClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationSQS()).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonSQSAsync getClientSQSAsync(final ExecutorFactory executorFactory) {
        return AmazonSQSAsyncClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationSQS()).
                withExecutorFactory(executorFactory).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonSNS getClientSNS() {
        return AmazonSNSClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationSNS()).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonSNSAsync getClientSNSAsync() {
        return AmazonSNSAsyncClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationSNS()).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonSNSAsync getClientSNSAsync(final ExecutorFactory executorFactory) {
        return AmazonSNSAsyncClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationSNS()).
                withExecutorFactory(executorFactory).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AWSLambda getClientLambda() {
        return AWSLambdaClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationLambda()).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AWSLambdaAsync getClientLambdaAsync() {
        return AWSLambdaAsyncClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationLambda()).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AWSLambdaAsync getClientLambdaAsync(final ExecutorFactory executorFactory) {
        return AWSLambdaAsyncClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationLambda()).
                withExecutorFactory(executorFactory).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonS3 getClientS3() {
        AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationS3()).
                withCredentials(getCredentialsProvider());
        builder.setPathStyleAccessEnabled(true);
        return builder.build();
    }

    public static AmazonS3 getClientS3SSL() {
        AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationS3SSL()).
                withCredentials(getCredentialsProvider());
        builder.setPathStyleAccessEnabled(true);
        return builder.build();
    }

    public static AWSSecretsManager getClientSecretsManager() {
        return AWSSecretsManagerClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationSecretsManager()).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonKinesis getClientKinesis() {
        return AmazonKinesisClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationKinesis()).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonKinesisAsync getClientKinesisAsync() {
        return AmazonKinesisAsyncClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationKinesis()).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonKinesisAsync getClientKinesisAsync(final ExecutorFactory executorFactory) {
        return AmazonKinesisAsyncClientBuilder.standard().
                withEndpointConfiguration(getEndpointConfigurationKinesis()).
                withExecutorFactory(executorFactory).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AWSCredentialsProvider getCredentialsProvider() {
        return new AWSStaticCredentialsProvider(TEST_CREDENTIALS);
    }

    protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationLambda() {
        return getEndpointConfiguration(Localstack.getEndpointLambda());
    }

    protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationKinesis() {
        return getEndpointConfiguration(Localstack.getEndpointKinesis());
    }

    protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationSQS() {
        return getEndpointConfiguration(Localstack.getEndpointSQS());
    }

    protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationS3() {
        return getEndpointConfiguration(Localstack.getEndpointS3());
    }

    protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationSNS() {
        return getEndpointConfiguration(Localstack.getEndpointSNS());
    }

    protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationS3SSL() {
        return getEndpointConfiguration(Localstack.getEndpointS3(true));
    }

    protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationSecretsManager() {
        return getEndpointConfiguration(Localstack.getEndpointSecretsmanager());
    }

    protected static AwsClientBuilder.EndpointConfiguration getEndpointConfigurationStepFunctions() {
        return getEndpointConfiguration(Localstack.getEndpointStepFunctions());
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

    public static void copyFolder(Path src, Path dest) throws IOException {
        try(Stream<Path> stream = Files.walk(src)) {
            stream.forEach(source -> copy(source, dest.resolve(src.relativize(source))));
        }
    }

    private static String[] excludedDirectories = {".github", ".git", ".idea", ".venv", "target", "node_modules"};

    public static void copy(Path source, Path dest) {
        try {
            CopyOption[] options = new CopyOption[] {StandardCopyOption.COPY_ATTRIBUTES, StandardCopyOption.REPLACE_EXISTING};
            if (Files.exists(dest)) {
                if(Files.isDirectory(dest)
                        || Arrays.stream(excludedDirectories)
                            .anyMatch( excluded -> source.toAbsolutePath().toString().contains(excluded))) {
                    // continue without copying
                    return;
                }
                try(FileChannel sourceFile = FileChannel.open(source)) {
                    try (FileChannel destFile = FileChannel.open(dest)) {
                        if (!Files.getLastModifiedTime(source).equals(Files.getLastModifiedTime(dest))
                                || sourceFile.size() != destFile.size()
                        ) {
                            Files.copy(source, dest, options);
                        }
                    }
                }
            } else {
                Files.copy(source, dest, options);
            }
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
