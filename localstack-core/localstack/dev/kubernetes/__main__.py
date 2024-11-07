import os

import click
import yaml

from localstack import version as localstack_version


def generate_k8s_cluster_config(pro: bool = False, mount_moto: bool = False, port: int = 4566):
    volumes = []
    root_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
    localstack_code_path = os.path.join(root_path, "localstack-core", "localstack")
    volumes.append(
        {
            "volume": f"{os.path.normpath(localstack_code_path)}:/code/localstack",
            "nodeFilters": ["server:*", "agent:*"],
        }
    )

    egg_path = os.path.join(
        root_path, "localstack-core", "localstack_core.egg-info/entry_points.txt"
    )
    volumes.append(
        {
            "volume": f"{os.path.normpath(egg_path)}:/code/entry_points_community",
            "nodeFilters": ["server:*", "agent:*"],
        }
    )
    if pro:
        pro_path = os.path.join(root_path, "..", "localstack-ext")
        pro_code_path = os.path.join(pro_path, "localstack-pro-core", "localstack", "pro", "core")
        volumes.append(
            {
                "volume": f"{os.path.normpath(pro_code_path)}:/code/localstack_ext",
                "nodeFilters": ["server:*", "agent:*"],
            }
        )

        egg_path = os.path.join(
            pro_path, "localstack-pro-core", "localstack_ext.egg-info/entry_points.txt"
        )
        volumes.append(
            {
                "volume": f"{os.path.normpath(egg_path)}:/code/entry_points_ext",
                "nodeFilters": ["server:*", "agent:*"],
            }
        )

    if mount_moto:
        moto_path = os.path.join(root_path, "..", "moto", "moto")
        volumes.append(
            {"volume": f"{moto_path}:/code/moto", "nodeFilters": ["server:*", "agent:*"]}
        )

    ports = [{"port": f"{port}:31566", "nodeFilters": ["server:0"]}]

    config = {"apiVersion": "k3d.io/v1alpha5", "kind": "Simple", "volumes": volumes, "ports": ports}

    return config


def snake_to_kebab_case(string: str):
    return string.lower().replace("_", "-")


def generate_k8s_cluster_overrides(
    pro: bool = False, cluster_config: dict = None, env: list[str] | None = None
):
    volumes = []
    for volume in cluster_config["volumes"]:
        name = snake_to_kebab_case(volume["volume"].split(":")[-1].split("/")[-1])
        volume_type = "Directory" if name != "entry-points" else "File"
        volumes.append(
            {
                "name": name,
                "hostPath": {"path": volume["volume"].split(":")[-1], "type": volume_type},
            }
        )

    volume_mounts = []
    target_path = "/opt/code/localstack/"
    venv_path = os.path.join(target_path, ".venv", "lib", "python3.11", "site-packages")
    for volume in volumes:
        if volume["name"] == "entry-points":
            entry_points_path = os.path.join(
                target_path, "localstack_core.egg-info", "entry_points.txt"
            )
            if pro:
                project = "localstack_ext-"
                version = localstack_version.__version__
                dist_info = f"{project}{version}0.dist-info"
                entry_points_path = os.path.join(venv_path, dist_info, "entry_points.txt")

            volume_mounts.append(
                {
                    "name": volume["name"],
                    "readOnly": True,
                    "mountPath": entry_points_path,
                }
            )
            continue

        volume_mounts.append(
            {
                "name": volume["name"],
                "readOnly": True,
                "mountPath": os.path.join(venv_path, volume["hostPath"]["path"].split("/")[-1]),
            }
        )

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
        extra_env_vars.append(
            {
                "name": "LOCALSTACK_AUTH_TOKEN",
                "value": "test",
            }
        )

    image_repository = "localstack/localstack-pro" if pro else "localstack/localstack"

    overrides = {
        "debug": True,
        "volumes": volumes,
        "volumeMounts": volume_mounts,
        "extraEnvVars": extra_env_vars,
        "image": {"repository": image_repository},
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

    config = generate_k8s_cluster_config(pro=pro, mount_moto=mount_moto, port=port)

    overrides = generate_k8s_cluster_overrides(pro, config, env=env)

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
