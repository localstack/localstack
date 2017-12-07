package cloud.localstack.docker.command;

import java.util.Arrays;

public class StopCommand extends Command {

    private final String containerId;

    public StopCommand(String containerId) {
        this.containerId = containerId;
    }

    public void execute() {
        dockerExe.execute(Arrays.asList("stop", containerId));
    }
}
