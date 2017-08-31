package cloud.localstack;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;
import org.ow2.proactive.process_tree_killer.ProcessTree;

import com.amazonaws.util.IOUtils;

/**
 * Simple JUnit test runner that automatically downloads, installs, starts,
 * and stops the LocalStack local cloud infrastructure components.
 *
 * Should work cross-OS, however has been only tested under Unix (Linux/MacOS).
 *
 * @author Waldemar Hummer
 */
public class LocalstackTestRunner extends BlockJUnit4ClassRunner {
	private static final Logger LOG = Logger.getLogger(LocalstackTestRunner.class.getName());

	private static final AtomicReference<Process> INFRA_STARTED = new AtomicReference<Process>();
	private static String CONFIG_FILE_CONTENT = "";

	private static final String INFRA_READY_MARKER = "Ready.";
	private static final String TMP_INSTALL_DIR = System.getProperty("java.io.tmpdir") +
			File.separator + "localstack_install_dir";
	private static final String ADDITIONAL_PATH = "/usr/local/bin/";
	private static final String LOCALHOST = "localhost";
	private static final String LOCALSTACK_REPO_URL = "https://github.com/localstack/localstack";

	public static final String ENV_CONFIG_USE_SSL = "USE_SSL";
	private static final String ENV_LOCALSTACK_PROCESS_GROUP = "ENV_LOCALSTACK_PROCESS_GROUP";

	public LocalstackTestRunner(Class<?> klass) throws InitializationError {
		super(klass);
	}

	/* SERVICE ENDPOINTS */

	public static String getEndpointS3() {
		String s3Endpoint = ensureInstallationAndGetEndpoint("s3");
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
		return ensureInstallationAndGetEndpoint("kinesis");
	}

	public static String getEndpointLambda() {
		return ensureInstallationAndGetEndpoint("lambda");
	}

	public static String getEndpointDynamoDB() {
		return ensureInstallationAndGetEndpoint("dynamodb");
	}

	public static String getEndpointDynamoDBStreams() {
		return ensureInstallationAndGetEndpoint("dynamodbstreams");
	}

	public static String getEndpointAPIGateway() {
		return ensureInstallationAndGetEndpoint("apigateway");
	}

	public static String getEndpointElasticsearch() {
		return ensureInstallationAndGetEndpoint("elasticsearch");
	}

	public static String getEndpointElasticsearchService() {
		return ensureInstallationAndGetEndpoint("es");
	}

	public static String getEndpointFirehose() {
		return ensureInstallationAndGetEndpoint("firehose");
	}

	public static String getEndpointSNS() {
		return ensureInstallationAndGetEndpoint("sns");
	}

	public static String getEndpointSQS() {
		return ensureInstallationAndGetEndpoint("sqs");
	}

	public static String getEndpointRedshift() {
		return ensureInstallationAndGetEndpoint("redshift");
	}

	public static String getEndpointSES() {
		return ensureInstallationAndGetEndpoint("ses");
	}

	public static String getEndpointRoute53() {
		return ensureInstallationAndGetEndpoint("route53");
	}

	public static String getEndpointCloudFormation() {
		return ensureInstallationAndGetEndpoint("cloudformation");
	}

	public static String getEndpointCloudWatch() {
		return ensureInstallationAndGetEndpoint("cloudwatch");
	}

	@Override
	public void run(RunNotifier notifier) {
		setupInfrastructure();
		super.run(notifier);
	}

	/* UTILITY METHODS */

	private static void ensureInstallation() {
		File dir = new File(TMP_INSTALL_DIR);
		File constantsFile = new File(dir, "localstack/constants.py");
		String logMsg = "Installing LocalStack to temporary directory (this may take a while): " + TMP_INSTALL_DIR;
		boolean messagePrinted = false;
		if(!constantsFile.exists()) {
			LOG.info(logMsg);
			messagePrinted = true;
			try {
				FileUtils.deleteDirectory(dir);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
			exec("git clone " + LOCALSTACK_REPO_URL + " " + TMP_INSTALL_DIR);
		}
		File installationDoneMarker = new File(dir, "localstack/infra/installation.finished.marker");
		if(!installationDoneMarker.exists()) {
			if(!messagePrinted) {
				LOG.info(logMsg);
			}
			exec("cd \"" + TMP_INSTALL_DIR + "\"; make install");
			/* create marker file */
			try {
				installationDoneMarker.createNewFile();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
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
		ensureInstallation();
		return getEndpoint(service);
	}

	public static boolean useSSL() {
		return isEnvConfigSet(ENV_CONFIG_USE_SSL);
	}

	public static boolean isEnvConfigSet(String configName) {
		String value = System.getenv(configName);
		return value != null && !Arrays.asList("false", "0", "").contains(value.trim());
	}

	private static String getEndpoint(String service) {
		if("".equals(CONFIG_FILE_CONTENT)) {
			readConfigFile();
		}
		String variableName = "DEFAULT_PORT_" + service.toUpperCase();
		String regex = ".*" + variableName + "\\s*=\\s*([0-9]+).*";
		String port = Pattern.compile(regex, Pattern.DOTALL | Pattern.MULTILINE).matcher(CONFIG_FILE_CONTENT).replaceAll("$1");
		String protocol = "http";
		if (useSSL()) {
			protocol = "https";
		}
		return protocol + "://" + LOCALHOST + ":" + port + "/";
	}

	private static Process exec(String ... cmd) {
		return exec(true, cmd);
	}

	private static Process exec(boolean wait, String ... cmd) {
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
				if(code != 0) {
					String stderr = IOUtils.toString(p.getErrorStream());
					String stdout = IOUtils.toString(p.getInputStream());
					throw new IllegalStateException("Failed to run command '" + String.join(" ", cmd) + "', return code " + code +
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

	private static void readConfigFile() {
		try {
			String configFile = TMP_INSTALL_DIR + File.separator + "localstack" +  File.separator + "constants.py";
			CONFIG_FILE_CONTENT = IOUtils.toString(new FileInputStream(configFile));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private void setupInfrastructure() {
		synchronized (INFRA_STARTED) {
			// make sure everything is installed locally
			ensureInstallation();
			// make sure we avoid any errors related to locally generated SSL certificates
			TestUtils.disableSslCertChecking();

			if(INFRA_STARTED.get() != null) return;
			String[] cmd = new String[]{"make", "-C", TMP_INSTALL_DIR, "infra"};
			Process proc;
			try {
				proc = exec(false, cmd);
				BufferedReader r1 = new BufferedReader(new InputStreamReader(proc.getInputStream()));
				String line;
				LOG.info("Waiting for infrastructure to be spun up");
				boolean ready = false;
				String output = "";
				while((line = r1.readLine()) != null) {
					output += line + "\n";
					if(INFRA_READY_MARKER.equals(line)) {
						ready = true;
						break;
					}
				}
				if(!ready) {
					throw new RuntimeException("Unable to start local infrastructure. Debug output: " + output);
				}
				/* read contents of LocalStack config file */
				readConfigFile();
				INFRA_STARTED.set(proc);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}

	public static void teardownInfrastructure() {
		Process proc = INFRA_STARTED.get();
		if(proc == null) {
			return;
		}
		killProcess(proc);
	}

	public static String getDefaultRegion() {
		return TestUtils.DEFAULT_REGION;
	}
}
