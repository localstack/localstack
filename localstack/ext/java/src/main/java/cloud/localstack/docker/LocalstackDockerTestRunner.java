package cloud.localstack.docker;

import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

import cloud.localstack.ServiceName;
import cloud.localstack.docker.annotation.IHostNameResolver;
import cloud.localstack.docker.annotation.LocalstackDockerProperties;
import cloud.localstack.docker.command.RegexStream;

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

    private static final String PORT_CONFIG_FILENAME = "/opt/code/localstack/.venv/lib/python2.7/site-packages/localstack_client/config.py";

    private static final Pattern READY_TOKEN = Pattern.compile("Ready\\.");

    //Regular expression used to parse localstack config to determine default ports for services
    private static final Pattern DEFAULT_PORT_PATTERN = Pattern.compile("'(\\w+)'\\Q: '{proto}://{host}:\\E(\\d+)'");
    private static final int SERVICE_NAME_GROUP = 1;
    private static final int PORT_GROUP = 2;


    private static Container localStackContainer;

    public static Container getLocalStackContainer() {
        return localStackContainer;
    }

    /**
     * This is a mapping from service name to internal ports.  In order to use them, the
     * internal port must be resolved to an external docker port via Container.getExternalPortFor()
     */
    private static Map<String, Integer> serviceToPortMap;

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
            loadServiceToPortMap();

            LOG.info("Waiting for localstack container to be ready...");
            localStackContainer.waitForLogToken(READY_TOKEN);

            super.run(notifier);
        }
        finally {
            localStackContainer.stop();
        }
    }


    private void loadServiceToPortMap() {
        String localStackPortConfig = localStackContainer.executeCommand(Arrays.asList("cat", PORT_CONFIG_FILENAME));

        Map<String, Integer> ports =  new RegexStream(DEFAULT_PORT_PATTERN.matcher(localStackPortConfig)).stream()
                .collect(Collectors.toMap(match -> match.group(SERVICE_NAME_GROUP),
                                            match -> Integer.parseInt(match.group(PORT_GROUP))));

        serviceToPortMap = Collections.unmodifiableMap(ports);
    }


    public static String getEndpointS3() {
        String s3Endpoint = endpointForService(ServiceName.S3);
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
        return endpointForService(ServiceName.KINESIS);
    }

    public static String getEndpointLambda() {
        return endpointForService(ServiceName.LAMBDA);
    }

    public static String getEndpointDynamoDB() {
        return endpointForService(ServiceName.DYNAMO);
    }

    public static String getEndpointDynamoDBStreams() {
        return endpointForService(ServiceName.DYNAMO_STREAMS);
    }

    public static String getEndpointAPIGateway() {
        return endpointForService(ServiceName.API_GATEWAY);
    }

    public static String getEndpointElasticsearch() {
        return endpointForService(ServiceName.ELASTICSEARCH);
    }

    public static String getEndpointElasticsearchService() {
        return endpointForService(ServiceName.ELASTICSEARCH_SERVICE);
    }

    public static String getEndpointFirehose() {
        return endpointForService(ServiceName.FIREHOSE);
    }

    public static String getEndpointSNS() {
        return endpointForService(ServiceName.SNS);
    }

    public static String getEndpointSQS() {
        return endpointForService(ServiceName.SQS);
    }

    public static String getEndpointRedshift() {
        return endpointForService(ServiceName.REDSHIFT);
    }

    public static String getEndpointSES() {
        return endpointForService(ServiceName.SES);
    }

    public static String getEndpointRoute53() {
        return endpointForService(ServiceName.ROUTE53);
    }

    public static String getEndpointCloudFormation() {
        return endpointForService(ServiceName.CLOUDFORMATION);
    }

    public static String getEndpointCloudWatch() {
        return endpointForService(ServiceName.CLOUDWATCH);
    }

    public static String getEndpointSSM() {
        return endpointForService(ServiceName.SSM);
    }


    public static String endpointForService(String serviceName) {
        if(serviceToPortMap == null) {
            throw new IllegalStateException("Service to port mapping has not been determined yet.");
        }

        if(!serviceToPortMap.containsKey(serviceName)) {
            throw new IllegalArgumentException("Unknown port mapping for service");
        }

        int internalPort = serviceToPortMap.get(serviceName);
        return endpointForPort(internalPort);
    }


    public static String endpointForPort(int port) {
        if (localStackContainer != null) {
            int externalPort = localStackContainer.getExternalPortFor(port);
            return String.format("http://%s:%s", externalHostName, externalPort);
        }

        throw new RuntimeException("Container not started");
    }
}