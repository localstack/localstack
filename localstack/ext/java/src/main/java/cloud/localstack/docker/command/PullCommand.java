package cloud.localstack.docker.command;

import java.util.Arrays;

public class PullCommand extends Command {

    private static final int PULL_COMMAND_TIMEOUT_MINUTES = 10;
    private static final String LATEST_TAG = "latest";

    private final String imageName;

    public PullCommand(String imageName) {
        this.imageName = imageName;
    }


    public void execute() {
        String image = String.format("%s:%s", imageName, LATEST_TAG);
        dockerExe.execute(Arrays.asList("pull", image), PULL_COMMAND_TIMEOUT_MINUTES);
    }
}
