package cloud.localstack.docker.annotation;

import com.amazonaws.util.EC2MetadataUtils;

/**
 * Finds the hostname of the current EC2 instance
 *
 * This is useful for a CI server that is itself a docker container and which mounts the docker unix socket
 * from the host machine.  In that case, the server cannot spawn child containers but will instead spawn sibling
 * containers which cannot be addressed at "localhost".  In order to address the sibling containers you need to resolve
 * the hostname of the host machine, which this method will accomplish.
 *
 * For more information about running docker for CI and mounting the host socket please look here:
 * http://jpetazzo.github.io/2015/09/03/do-not-use-docker-in-docker-for-ci/
 */
public class EC2HostNameResolver implements IHostNameResolver {

    @Override
    public String getHostName() {
        return EC2MetadataUtils.getLocalHostName();
    }

}
