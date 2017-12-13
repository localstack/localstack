package cloud.localstack.docker;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static java.util.stream.Collectors.joining;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * A wrapper around the docker executable process. The DOCKER_LOCATION environment variable
 * can be used if docker is not installed in a default location.
 */
public class DockerExe {

    private static final int WAIT_TIMEOUT_MINUTES = 3;

    private static final List<String> POSSIBLE_EXE_LOCATIONS = Arrays.asList(
            System.getenv("DOCKER_LOCATION"),
            "C:/program files/docker/docker/resources/bin/docker.exe",
            "/usr/local/bin/docker",
            "/usr/bin/docker");


    private final String exeLocation;


    public DockerExe() {
        this.exeLocation = getDockerExeLocation();
    }


    private String getDockerExeLocation() {
        return POSSIBLE_EXE_LOCATIONS.stream()
                .filter(Objects::nonNull)
                .filter(name -> new File(name).exists())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Cannot find docker executable."));
    }


    public String execute(List<String> args) {
        try {
            List<String> command = new ArrayList<>();
            command.add(exeLocation);
            command.addAll(args);

            Process process = new ProcessBuilder()
                    .command(command)
                    .redirectErrorStream(true)
                    .start();

            ExecutorService exec = newSingleThreadExecutor();
            Future<String> outputFuture = exec.submit(() -> handleOutput(process));

            String output = outputFuture.get(WAIT_TIMEOUT_MINUTES, TimeUnit.MINUTES);
            process.waitFor(WAIT_TIMEOUT_MINUTES, TimeUnit.MINUTES);
            exec.shutdown();

            return output;
        } catch (Exception ex) {
            throw new RuntimeException("Failed to execute command", ex);
        }
    }


    private String handleOutput(Process process) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), UTF_8));
        return reader.lines().collect(joining(System.lineSeparator()));
    }
}
