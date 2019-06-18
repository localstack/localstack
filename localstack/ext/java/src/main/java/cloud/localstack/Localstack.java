package cloud.localstack;

import com.amazonaws.util.IOUtils;
import org.ow2.proactive.process_tree_killer.ProcessTree;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Singleton class that automatically downloads, installs, starts,
 * and stops the LocalStack local cloud infrastructure components.
 *
 * Should work cross-OS, however has been only tested under Unix (Linux/MacOS).
 *
 * @author Waldemar Hummer
 * @author Patrick Allain - 5/3/18.
 */
public class Localstack {

    /** Single instance...  */
    protected static final Localstack INSTANCE = new Localstack();

    private static final Logger LOG = Logger.getLogger(Localstack.class.getName());

    private static final AtomicReference<Process> INFRA_STARTED = new AtomicReference<Process>();

    private static final String INFRA_READY_MARKER = "Ready.";

    private static final String TMP_INSTALL_DIR = System.getProperty("java.io.tmpdir") +
            File.separator + "localstack_install_dir";

    private static final String CURRENT_DEV_DIR;

    private static boolean DEV_ENVIRONMENT;

    private static final String ADDITIONAL_PATH = "/usr/local/bin/";

    private static final String LOCALSTACK_REPO_URL = "https://github.com/localstack/localstack";

    public static final String ENV_CONFIG_USE_SSL = "USE_SSL";

    private static final String ENV_LOCALSTACK_PROCESS_GROUP = "ENV_LOCALSTACK_PROCESS_GROUP";

    static {
        // Determine if we are running in a development environment for localstack
        Path currentDirectory = Paths.get(".").toAbsolutePath().getParent();
        Path localstackDir = Optional.ofNullable(currentDirectory)
                .map(Path::getParent).map(Path::getParent).map(Path::getParent).orElse(null);
        if( currentDirectory != null && localstackDir != null
                && currentDirectory.getFileName().toString().equals("java")
                && localstackDir.getFileName().toString().equals("localstack")) {
            CURRENT_DEV_DIR = localstackDir.toString();
            Path gitConfig = Paths.get(CURRENT_DEV_DIR, ".git", "config");

            if(Files.exists(gitConfig)) {
                setIsDevEnvironment(gitConfig);
            } else {
                DEV_ENVIRONMENT = false;
            }
        } else {
            CURRENT_DEV_DIR = currentDirectory.toAbsolutePath().toString();
            DEV_ENVIRONMENT = false;
        }
    }

    private Localstack() {

    }

    public static boolean isDevEnvironment() {
        return DEV_ENVIRONMENT;
    }

    private static void setIsDevEnvironment(Path gitConfig) {
        Pattern remoteOrigin = Pattern.compile("^\\[remote \"origin\"]");
        Pattern localstackGit = Pattern.compile(".+\\/localstack\\.git$");
        boolean remoteOriginFound = false;
        try {
            try(Stream<String> lines = Files.lines(gitConfig)){
                for(String line : lines.collect(Collectors.toList())) {
                    if(remoteOriginFound) {
                        if(localstackGit.matcher(line).matches()) {
                            DEV_ENVIRONMENT = true;
                        } else {
                            DEV_ENVIRONMENT = false;
                        }
                        break;
                    }

                    if( remoteOrigin.matcher(line).matches() ) {
                        remoteOriginFound = true;
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /* SERVICE ENDPOINTS */

    public static String getEndpointS3() {
        return getEndpointS3(false);
    }

    public static String getEndpointS3(boolean override_SSL) {
        String s3Endpoint = ensureInstallationAndGetEndpoint(ServiceName.S3, override_SSL);
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
        return ensureInstallationAndGetEndpoint(ServiceName.KINESIS);
    }

    public static String getEndpointLambda() {
        return ensureInstallationAndGetEndpoint(ServiceName.LAMBDA);
    }

    public static String getEndpointDynamoDB() {
        return ensureInstallationAndGetEndpoint(ServiceName.DYNAMO);
    }

    public static String getEndpointDynamoDBStreams() {
        return ensureInstallationAndGetEndpoint(ServiceName.DYNAMO_STREAMS);
    }

    public static String getEndpointAPIGateway() {
        return ensureInstallationAndGetEndpoint(ServiceName.API_GATEWAY);
    }

    public static String getEndpointElasticsearch() {
        return ensureInstallationAndGetEndpoint(ServiceName.ELASTICSEARCH);
    }

    public static String getEndpointElasticsearchService() {
        return ensureInstallationAndGetEndpoint(ServiceName.ELASTICSEARCH_SERVICE);
    }

    public static String getEndpointFirehose() {
        return ensureInstallationAndGetEndpoint(ServiceName.FIREHOSE);
    }

    public static String getEndpointSNS() {
        return ensureInstallationAndGetEndpoint(ServiceName.SNS);
    }

    public static String getEndpointSQS() {
        return ensureInstallationAndGetEndpoint(ServiceName.SQS);
    }

    public static String getEndpointRedshift() {
        return ensureInstallationAndGetEndpoint(ServiceName.REDSHIFT);
    }

    public static String getEndpointSES() {
        return ensureInstallationAndGetEndpoint(ServiceName.SES);
    }

    public static String getEndpointRoute53() {
        return ensureInstallationAndGetEndpoint(ServiceName.ROUTE53);
    }

    public static String getEndpointCloudFormation() {
        return ensureInstallationAndGetEndpoint(ServiceName.CLOUDFORMATION);
    }

    public static String getEndpointCloudWatch() {
        return ensureInstallationAndGetEndpoint(ServiceName.CLOUDWATCH);
    }

    public static String getEndpointSSM() {
        return ensureInstallationAndGetEndpoint(ServiceName.SSM);
    }

    public static String getEndpointSecretsmanager() {
        return ensureInstallationAndGetEndpoint(ServiceName.SECRETSMANAGER);
    }

    public static String getEndpointStepFunctions() {
        return ensureInstallationAndGetEndpoint(ServiceName.STEPFUNCTIONS);
    }

    public static String getEndpointEC2() {
        return ensureInstallationAndGetEndpoint(ServiceName.EC2);
    }


    /* UTILITY METHODS */

    /**
     * Installs localstack into a temporary directory
     * If DEV_ENVIRONMENT for localstack is detected also copies over any changed files
     */
    private static void ensureInstallation() {
        ensureInstallation(false);
    }

    private static void ensureInstallation(boolean initialSetup) {
        File dir = new File(TMP_INSTALL_DIR);
        File constantsFile = new File(dir, "localstack/constants.py");
        String logMsg = "Installing LocalStack to temporary directory (this may take a while): " + TMP_INSTALL_DIR;
        boolean messagePrinted = false;
        if (!constantsFile.exists()) {
            LOG.info(logMsg);
            messagePrinted = true;
            deleteDirectory(dir);
            exec("git clone " + LOCALSTACK_REPO_URL + " " + TMP_INSTALL_DIR);
        }

        if(DEV_ENVIRONMENT && initialSetup) {
            // Copy changed files over
            Path localstackDir = Paths.get(CURRENT_DEV_DIR);
            Path tempLocalstackDir = Paths.get(TMP_INSTALL_DIR);
            try {
                TestUtils.copyFolder(localstackDir, tempLocalstackDir);
            } catch (IOException e) {
                throw new RuntimeException(e.getMessage(), e);
            }

            ensureJavaFilesRefreshedForDev();
        }

        File installationDoneMarker = new File(dir, "localstack/infra/installation.finished.marker");
        if ( (DEV_ENVIRONMENT && initialSetup) || !installationDoneMarker.exists()) {
            if (!messagePrinted) {
                LOG.info(logMsg);
            }
            String useSSL = useSSL() ? "USE_SSL=1" : "";
            exec("cd \"" + TMP_INSTALL_DIR + "\";"+useSSL+" make install");
            /* create marker file */
            try {
                installationDoneMarker.createNewFile();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static void deleteDirectory(File dir) {
        try {
            if (dir.exists())
                Files.walk(dir.toPath())
                        .sorted(Comparator.reverseOrder())
                        .map(Path::toFile)
                        .forEach(File::delete);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void killProcess(Process p) {
        try {
            ProcessTree.get().killAll(Collections.singletonMap(
                    ENV_LOCALSTACK_PROCESS_GROUP, ENV_LOCALSTACK_PROCESS_GROUP));
        } catch (Exception e) {
            LOG.warning("Unable to terminate processes: " + e);
        }
    }

    private static String ensureInstallationAndGetEndpoint(String service) {
        return ensureInstallationAndGetEndpoint(service,false);
    }

    private static String ensureInstallationAndGetEndpoint(String service, boolean override_SSL) {
        ensureInstallation();
        return getEndpoint(service, override_SSL);
    }

    public static boolean useSSL() {
        return isEnvConfigSet(ENV_CONFIG_USE_SSL);
    }

    public static boolean isEnvConfigSet(String configName) {
        String value = System.getenv(configName);
        return value != null && !Arrays.asList("false", "0", "").contains(value.trim());
    }

    /**
     * Gets the endpoint for the service, uses SSL if override_SSL or environmental config USE_SSL is set
     */
    private static String getEndpoint(String service, boolean override_SSL) {
        String useSSL = override_SSL || useSSL() ? "USE_SSL=1" : "";
        String cmd = "cd '" + TMP_INSTALL_DIR + "'; "
                + ". .venv/bin/activate; "
                + useSSL + " python -c 'import localstack_client.config; "
                + "print(localstack_client.config.get_service_endpoint(\"" + service + "\"))'";
        Process p = exec(cmd);
        try {
            return IOUtils.toString(p.getInputStream()).trim();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Process exec(String... cmd) {
        return exec(true, cmd);
    }

    private static Process exec(boolean wait, String... cmd) {
        try {
            if (cmd.length == 1 && !new File(cmd[0]).exists()) {
                cmd = new String[]{"bash", "-c", cmd[0]};
            }
            Map<String, String> env = new HashMap<>(System.getenv());
            ProcessBuilder builder = new ProcessBuilder(cmd);
            builder.environment().put("PATH", ADDITIONAL_PATH + ":" + env.get("PATH"));
            builder.environment().put(ENV_LOCALSTACK_PROCESS_GROUP, ENV_LOCALSTACK_PROCESS_GROUP);
            final Process p = builder.start();
            if (wait) {
                int code = p.waitFor();
                if (code != 0) {
                    String stderr = IOUtils.toString(p.getErrorStream());
                    String stdout = IOUtils.toString(p.getInputStream());
                    throw new IllegalStateException("Failed to run command '" + String.join(" ", cmd) + "', return " +
                            "code " + code +
                            ".\nSTDOUT: " + stdout + "\nSTDERR: " + stderr);
                }
            } else {
                /* make sure we destroy the process on JVM shutdown */
                Runtime.getRuntime().addShutdownHook(new Thread() {
                    public void run() {
                        killProcess(p);
                    }
                });
            }
            return p;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected void setupInfrastructure() {
        synchronized (INFRA_STARTED) {
            // make sure everything is installed locally
            ensureInstallation(true);

            // make sure we avoid any errors related to locally generated SSL certificates
            TestUtils.disableSslCertChecking();

            if (INFRA_STARTED.get() != null) return;
            String[] cmd = new String[]{"make", "-C", TMP_INSTALL_DIR, "infra"};
            Process proc;
            try {
                proc = exec(false, cmd);
                BufferedReader r1 = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                String line;
                LOG.info(TMP_INSTALL_DIR);
                LOG.info("Waiting for infrastructure to be spun up");
                boolean ready = false;
                String output = "";
                while ((line = r1.readLine()) != null) {
                    output += line + "\n";
                    if (INFRA_READY_MARKER.equals(line)) {
                        ready = true;
                        break;
                    }
                }
                if (!ready) {
                    throw new RuntimeException("Unable to start local infrastructure. Debug output: " + output);
                }
                INFRA_STARTED.set(proc);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Compiles the localstack-utils-fat and localstack-utils-tests jars and copies them to the localstack tmp install
     * directory.
     */
    private static void ensureJavaFilesRefreshedForDev() {
        String[] cmdPrepareJava = new String[]{"make", "-C", CURRENT_DEV_DIR
                , "prepare-java-tests-infra-jars"};
        exec(true, cmdPrepareJava);
        Path currentInfraPath = Paths.get(CURRENT_DEV_DIR, "localstack", "infra");
        Path tmpInfraPath = Paths.get(TMP_INSTALL_DIR, "localstack", "infra");
        Path localstackUtilsFatJar = Paths.get(currentInfraPath.toString(), "localstack-utils-fat.jar");
        Path localstackUtilsTestsJar = Paths.get(currentInfraPath.toString(), "localstack-utils-tests.jar");

        if(Files.exists(localstackUtilsFatJar)) {
            Path tempInstallDirFatJar = Paths.get(tmpInfraPath.toString(), "localstack-utils-fat.jar");
            TestUtils.copy(localstackUtilsFatJar, tempInstallDirFatJar);
        }

        if(Files.exists(localstackUtilsTestsJar)) {
            Path tempInstallDirTestsJar = Paths.get(tmpInfraPath.toString(), "localstack-utils-tests.jar");
            TestUtils.copy(localstackUtilsTestsJar, tempInstallDirTestsJar);
        }
    }

    public static void teardownInfrastructure() {
        Process proc = INFRA_STARTED.get();
        if (proc == null) {
            return;
        }
        killProcess(proc);
        INFRA_STARTED.set(null);
    }

    public static String getDefaultRegion() {
        return TestUtils.DEFAULT_REGION;
    }
}
