import dataclasses
import os
from typing import Literal

import click
import yaml


@dataclasses.dataclass
class MountPoint:
    name: str
    host_path: str
    container_path: str
    node_path: str
    read_only: bool = True
    volume_type: Literal["Directory", "File"] = "Directory"


def generate_mount_points(
    pro: bool = False, mount_moto: bool = False, mount_entrypoints: bool = False
) -> list[MountPoint]:
    mount_points = []
    # host paths
    root_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
    localstack_code_path = os.path.join(root_path, "localstack-core", "localstack")
    pro_path = os.path.join(root_path, "..", "localstack-ext")

    # container paths
    target_path = "/opt/code/localstack/"
    venv_path = os.path.join(target_path, ".venv", "lib", "python3.11", "site-packages")

    # Community code
    if pro:
        # Pro installs community code as a package, so it lives in the venv site-packages
        mount_points.append(
            MountPoint(
                name="localstack",
                host_path=os.path.normpath(localstack_code_path),
                node_path="/code/localstack",
                container_path=os.path.join(venv_path, "localstack"),
                # Read only has to be false here, as we mount the pro code into this mount, as it is the entire namespace package
                read_only=False,
            )
        )
    else:
        # Community does not install the localstack package in the venv, but has the code directly in `/opt/code/localstack`
        mount_points.append(
            MountPoint(
                name="localstack",
                host_path=os.path.normpath(localstack_code_path),
                node_path="/code/localstack",
                container_path=os.path.join(target_path, "localstack-core", "localstack"),
            )
        )

    # Pro code
    if pro:
        pro_code_path = os.path.join(pro_path, "localstack-pro-core", "localstack", "pro", "core")
        mount_points.append(
            MountPoint(
                name="localstack-pro",
                host_path=os.path.normpath(pro_code_path),
                node_path="/code/localstack-pro",
                container_path=os.path.join(venv_path, "localstack", "pro", "core"),
            )
        )

    # entrypoints
    if mount_entrypoints:
        if pro:
            # Community entrypoints in pro image
            # TODO actual package version detection
            print(
                "WARNING: Package version detection is not implemented."
                "You need to adapt the version in the .egg-info paths to match the package version installed in the used localstack-pro image."
            )
            community_version = "4.1.1.dev14"
            pro_version = "4.1.1.dev16"
            egg_path = os.path.join(
                root_path, "localstack-core", "localstack_core.egg-info/entry_points.txt"
            )
            mount_points.append(
                MountPoint(
                    name="entry-points-community",
                    host_path=os.path.normpath(egg_path),
                    node_path="/code/entry-points-community",
                    container_path=os.path.join(
                        venv_path, f"localstack-{community_version}.egg-info", "entry_points.txt"
                    ),
                    volume_type="File",
                )
            )
            # Pro entrypoints in pro image
            egg_path = os.path.join(
                pro_path, "localstack-pro-core", "localstack_ext.egg-info/entry_points.txt"
            )
            mount_points.append(
                MountPoint(
                    name="entry-points-pro",
                    host_path=os.path.normpath(egg_path),
                    node_path="/code/entry-points-pro",
                    container_path=os.path.join(
                        venv_path, f"localstack_ext-{pro_version}.egg-info", "entry_points.txt"
                    ),
                    volume_type="File",
                )
            )
        else:
            # Community entrypoints in community repo
            # In the community image, the code is not installed as package, so the paths are predictable
            egg_path = os.path.join(
                root_path, "localstack-core", "localstack_core.egg-info/entry_points.txt"
            )
            mount_points.append(
                MountPoint(
                    name="entry-points-community",
                    host_path=os.path.normpath(egg_path),
                    node_path="/code/entry-points-community",
                    container_path=os.path.join(
                        target_path,
                        "localstack-core",
                        "localstack_core.egg-info",
                        "entry_points.txt",
                    ),
                    volume_type="File",
                )
            )

    if mount_moto:
        moto_path = os.path.join(root_path, "..", "moto", "moto")
        mount_points.append(
            MountPoint(
                name="moto",
                host_path=os.path.normpath(moto_path),
                node_path="/code/moto",
                container_path=os.path.join(venv_path, "moto"),
            )
        )
    return mount_points


def generate_k8s_cluster_config(mount_points: list[MountPoint], port: int = 4566):
    volumes = [
        {
            "volume": f"{mount_point.host_path}:{mount_point.node_path}",
            "nodeFilters": ["server:*", "agent:*"],
        }
        for mount_point in mount_points
    ]

    ports = [{"port": f"{port}:31566", "nodeFilters": ["server:0"]}]

    config = {"apiVersion": "k3d.io/v1alpha5", "kind": "Simple", "volumes": volumes, "ports": ports}

    return config


def snake_to_kebab_case(string: str):
    return string.lower().replace("_", "-")


def generate_k8s_cluster_overrides(
    mount_points: list[MountPoint], pro: bool = False, env: list[str] | None = None
):
    volumes = [
        {
            "name": mount_point.name,
            "hostPath": {"path": mount_point.node_path, "type": mount_point.volume_type},
        }
        for mount_point in mount_points
    ]

    volume_mounts = [
        {
            "name": mount_point.name,
            "readOnly": mount_point.read_only,
            "mountPath": mount_point.container_path,
        }
        for mount_point in mount_points
    ]

    extra_env_vars = []
    if env:
        for env_variable in env:
            lhs, _, rhs = env_variable.partition("=")
            extra_env_vars.append(
                {
                    "name": lhs,
                    "value": rhs,
                }
            )

    if pro:
        extra_env_vars += [
            {
                "name": "LOCALSTACK_AUTH_TOKEN",
                "value": "test",
            },
            {
                "name": "CONTAINER_RUNTIME",
                "value": "kubernetes",
            },
        ]

    image_repository = "localstack/localstack-pro" if pro else "localstack/localstack"

    overrides = {
        "debug": True,
        "volumes": volumes,
        "volumeMounts": volume_mounts,
        "extraEnvVars": extra_env_vars,
        "image": {"repository": image_repository},
        "lambda": {"executor": "kubernetes"},
    }

    return overrides


def write_file(content: dict, output_path: str, file_name: str):
    path = os.path.join(output_path, file_name)
    with open(path, "w") as f:
        f.write(yaml.dump(content))
        f.close()
        print(f"Generated file at {path}")


def print_file(content: dict, file_name: str):
    print(f"Generated file:\t{file_name}")
    print("=====================================")
    print(yaml.dump(content))
    print("=====================================")


@click.command("run")
@click.option(
    "--pro", is_flag=True, default=None, help="Mount the localstack-pro code into the cluster."
)
@click.option(
    "--mount-moto", is_flag=True, default=None, help="Mount the moto code into the cluster."
)
@click.option(
    "--mount-entrypoints", is_flag=True, default=None, help="Mount the entrypoints into the pod."
)
@click.option(
    "--write",
    is_flag=True,
    default=None,
    help="Write the configuration and overrides to files.",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    help="Output directory for generated files.",
)
@click.option(
    "--overrides-file",
    "-of",
    default=None,
    help="Name of the overrides file (default: overrides.yml).",
)
@click.option(
    "--config-file",
    "-cf",
    default=None,
    help="Name of the configuration file (default: configuration.yml).",
)
@click.option(
    "--env", "-e", default=None, help="Environment variable to set in the pod", multiple=True
)
@click.option(
    "--port",
    "-p",
    default=4566,
    help="Port to expose from the kubernetes node",
    type=click.IntRange(0, 65535),
)
@click.argument("command", nargs=-1, required=False)
def run(
    pro: bool = None,
    mount_moto: bool = False,
    mount_entrypoints: bool = False,
    write: bool = False,
    output_dir=None,
    overrides_file: str = None,
    config_file: str = None,
    command: str = None,
    env: list[str] = None,
    port: int = None,
):
    """
    A tool for localstack developers to generate the kubernetes cluster configuration file and the overrides to mount the localstack code into the cluster.
    """
    mount_points = generate_mount_points(pro, mount_moto, mount_entrypoints)

    config = generate_k8s_cluster_config(mount_points, port=port)

    overrides = generate_k8s_cluster_overrides(mount_points, pro=pro, env=env)

    output_dir = output_dir or os.getcwd()
    overrides_file = overrides_file or "overrides.yml"
    config_file = config_file or "configuration.yml"

    if write:
        write_file(config, output_dir, config_file)
        write_file(overrides, output_dir, overrides_file)
    else:
        print_file(config, config_file)
        print_file(overrides, overrides_file)

    overrides_file_path = os.path.join(output_dir, overrides_file)
    config_file_path = os.path.join(output_dir, config_file)

    print("\nTo create a k3d cluster with the generated configuration, follow these steps:")
    print("1. Run the following command to create the cluster:")
    print(f"\n    k3d cluster create --config {config_file_path}\n")

    print("2. Once the cluster is created, start LocalStack with the generated overrides:")
    print("\n    helm repo add localstack https://localstack.github.io/helm-charts # (if required)")
    print(
        f"\n    helm upgrade --install localstack localstack/localstack -f {overrides_file_path}\n"
    )


def main():
    run()


if __name__ == "__main__":
    main()
