package cloud.localstack.docker.command;

import java.util.Arrays;

public class PullCommand extends Command {

    private static final int PULL_COMMAND_TIMEOUT_MINUTES = 7;
    private static final String LATEST_TAG = "latest";

    private final String imageName;

    private final String imageTag;

    public PullCommand(String imageName) {
        this(imageName, null);
    }

    public PullCommand(String imageName, String imageTag) {
        this.imageName = imageName;
        this.imageTag = imageTag;
    }

    public void execute() {
        String image = String.format("%s:%s", imageName, imageTag == null ? LATEST_TAG : imageTag);
        dockerExe.execute(Arrays.asList("pull", image), PULL_COMMAND_TIMEOUT_MINUTES);
    }
}
