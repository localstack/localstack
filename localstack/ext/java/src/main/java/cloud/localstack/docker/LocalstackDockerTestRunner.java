package cloud.localstack.docker;

import java.lang.annotation.Annotation;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

import cloud.localstack.docker.annotation.IHostNameResolver;
import cloud.localstack.docker.annotation.LocalstackDockerProperties;

/**
 * JUnit test runner that automatically pulls and runs the latest localstack docker image
 * and then terminates when tests are complete.
 *
 * Having docker installed is a prerequisite for this test runner to execute.  If docker
 * is not installed in one of the default locations (C:\program files\docker\docker\resources\bin\, usr/local/bin or usr/bin)
 * then use the DOCKER_LOCATION environment variable to specify the location.
 *
 * Since ports are dynamically allocated, the external port needs to be resolved based on the default localstack port.
 *
 * The hostname defaults to localhost, but in some environments that is not sufficient, so the HostName can be specified
 * by using the LocalstackDockerProperties annotation with an IHostNameResolver.
 *
 * @author Alan Bevier
 */
public class LocalstackDockerTestRunner extends BlockJUnit4ClassRunner {

    private static final Logger LOG = Logger.getLogger(LocalstackDockerTestRunner.class.getName());

    //These are the default internal ports in the localstack docker image, in order to 
    //use them, they must be resolved to an external docker port via Container.getExternalPortFor()
    public static final int API_GATEWAY_INTERNAL_PORT = 4567;
    public static final int KINESIS_INTERNAL_PORT = 4568;
    public static final int DYNAMO_INTERNAL_PORT = 4569;
    public static final int DYNAMO_STREAMS_INTERNAL_PORT = 4570;
    public static final int ELASTICSEARCH_INTERNAL_PORT = 4571;
    public static final int S3_INTERNAL_PORT = 4572;
    public static final int FIREHOSE_INTERNAL_PORT = 4573;
    public static final int LAMBDA_INTERNAL_PORT = 4574;
    public static final int SNS_INTERNAL_PORT = 4575;
    public static final int SQS_INTERNAL_PORT = 4576;
    public static final int REDSHIFT_INTERNAL_PORT = 4577;
    public static final int ES_INTERNAL_PORT = 4578;
    public static final int SES_INTERNAL_PORT = 4579;
    public static final int ROUTE53_INTERNAL_PORT = 4580;
    public static final int CLOUDFORMATION_INTERNAL_PORT = 4581;
    public static final int CLOUDWATCH_INTERNAL_PORT = 4582;
    public static final int SSM_INTERNAL_PORT = 4583;

    private static final Pattern READY_TOKEN = Pattern.compile("Ready\\.");


    private static Container localStackContainer;

    public static Container getLocalStackContainer() {
        return localStackContainer;
    }


    private static String externalHostName = "localhost";


    public LocalstackDockerTestRunner(Class<?> klass) throws InitializationError {
        super(klass);
        processAnnotations(klass.getAnnotations());
    }


    private void processAnnotations(Annotation[] annotations) {
        for(Annotation annotation : annotations) {
            if(annotation instanceof LocalstackDockerProperties) {
                processDockerPropertiesAnnotation((LocalstackDockerProperties)annotation);
            }
        }
    }

    private void processDockerPropertiesAnnotation(LocalstackDockerProperties properties) {
        try {
            IHostNameResolver hostNameResolver = properties.hostNameResolver().newInstance();
            String resolvedName = hostNameResolver.getHostName();
            if(StringUtils.isNotBlank(resolvedName)) {
                externalHostName = resolvedName;
            }
            LOG.info("External host name is set to:" + externalHostName);
        }
        catch(InstantiationException | IllegalAccessException ex) {
            throw new IllegalStateException("Unable to resolve hostname", ex);
        }
    }


    @Override
    public void run(RunNotifier notifier) {
        localStackContainer = Container.createLocalstackContainer(externalHostName);
        try {

            LOG.info("Waiting for localstack container to be ready...");
            localStackContainer.waitForLogToken(READY_TOKEN);

            super.run(notifier);
        }
        finally {
            localStackContainer.stop();
        }
    }


    public static String getEndpointS3() {
        String s3Endpoint = endpointForPort(S3_INTERNAL_PORT);
        /*
         * Use the domain name wildcard *.localhost.atlassian.io which maps to 127.0.0.1
         * We need to do this because S3 SDKs attempt to access a domain <bucket-name>.<service-host-name>
         * which by default would result in <bucket-name>.localhost, but that name cannot be resolved
         * (unless hardcoded in /etc/hosts)
         */
        s3Endpoint = s3Endpoint.replace("localhost", "test.localhost.atlassian.io");
        return s3Endpoint;
    }


    public static String getEndpointKinesis() {
        return endpointForPort(KINESIS_INTERNAL_PORT);
    }

    public static String getEndpointLambda() {
        return endpointForPort(LAMBDA_INTERNAL_PORT);
    }

    public static String getEndpointDynamoDB() {
        return endpointForPort(DYNAMO_INTERNAL_PORT);
    }

    public static String getEndpointDynamoDBStreams() {
        return endpointForPort(DYNAMO_STREAMS_INTERNAL_PORT);
    }

    public static String getEndpointAPIGateway() {
        return endpointForPort(API_GATEWAY_INTERNAL_PORT);
    }

    public static String getEndpointElasticsearch() {
        return endpointForPort(ELASTICSEARCH_INTERNAL_PORT);
    }

    public static String getEndpointElasticsearchService() {
        return endpointForPort(ES_INTERNAL_PORT);
    }

    public static String getEndpointFirehose() {
        return endpointForPort(FIREHOSE_INTERNAL_PORT);
    }

    public static String getEndpointSNS() {
        return endpointForPort(SNS_INTERNAL_PORT);
    }

    public static String getEndpointSQS() {
        return endpointForPort(SQS_INTERNAL_PORT);
    }

    public static String getEndpointRedshift() {
        return endpointForPort(REDSHIFT_INTERNAL_PORT);
    }

    public static String getEndpointSES() {
        return endpointForPort(SES_INTERNAL_PORT);
    }

    public static String getEndpointRoute53() {
        return endpointForPort(ROUTE53_INTERNAL_PORT);
    }

    public static String getEndpointCloudFormation() {
        return endpointForPort(CLOUDFORMATION_INTERNAL_PORT);
    }

    public static String getEndpointCloudWatch() {
        return endpointForPort(CLOUDWATCH_INTERNAL_PORT);
    }

    public static String getEndpointSSM() {
        return endpointForPort(SSM_INTERNAL_PORT);
    }


    public static String endpointForPort(int port) {
        if (localStackContainer != null) {
            int externalPort = localStackContainer.getExternalPortFor(port);
            return String.format("http://%s:%s", externalHostName, externalPort);
        }

        throw new RuntimeException("Container not started");
    }
}