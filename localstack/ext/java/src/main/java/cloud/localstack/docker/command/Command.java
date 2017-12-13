package cloud.localstack.docker.command;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import cloud.localstack.docker.DockerExe;

public abstract class Command {

    protected final DockerExe dockerExe = new DockerExe();

    protected List<String> options = new ArrayList<>();

    protected void addOptions(String ...items) {
        options.addAll(Arrays.asList(items));
    }
}
