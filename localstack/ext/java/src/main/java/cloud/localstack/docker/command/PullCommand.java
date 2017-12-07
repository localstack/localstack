package cloud.localstack.docker.command;

import java.util.Arrays;

public class PullCommand extends Command {

    private static final String LATEST_TAG = "latest";

    private final String imageName;

    public PullCommand(String imageName) {
        this.imageName = imageName;
    }


    public void execute() {
        String image = String.format("%s:%s", imageName, LATEST_TAG);
        dockerExe.execute(Arrays.asList("pull", image));
    }
}
