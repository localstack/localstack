## Rootfull Podman

### With podman-docker
- https://archlinux.org/packages/community/x86_64/podman-docker/
- https://packages.debian.org/sid/podman-docker

```
systemctl start podman.service
DEBUG=1 localstack start
```

### Without podman-docker
```
systemctl start podman.service
DEBUG=1 DOCKER_CMD=podman DOCKER_HOST=unix://run/podman/podman.sock DOCKER_SOCK=/run/podman/podman.sock localstack start
```

## Rootless Podman
- https://wiki.archlinux.org/title/Podman#Rootless_Podman
- https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md
- https://www.redhat.com/sysadmin/controlling-access-rootless-podman-users ignore_chown_errors=true
- https://www.redhat.com/sysadmin/rootless-podman
- https://github.com/containers/podman/issues/7704

```
systemctl --user start podman.service
DEBUG=1 DOCKER_CMD="podman --log-level=debug --storage-opt overlay.ignore_chown_errors=true" DOCKER_SOCK=$XDG_RUNTIME_DIR/podman/podman.sock DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock localstack start
```

## Other
- https://www.redhat.com/sysadmin/podman-inside-container
