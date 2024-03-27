import os

import click
import yaml


def generate_k8s_cluster_config(
    pro: bool = False, mount_moto: bool = False, write_files: bool = False
):
    volumes = []
    root_path = os.path.join(os.path.dirname(__file__), "..", "..", "..")
    localstack_code_path = os.path.join(root_path, "localstack")
    volumes.append(
        {
            "volume": f"{os.path.normpath(localstack_code_path)}:/code/localstack",
            "nodeFilters": ["server:*", "agent:*"],
        }
    )

    egg_path = os.path.join(root_path, "localstack_core.egg-info")
    if pro:
        ext_path = os.path.join(root_path, "..", "localstack-ext")
        ext_code_path = os.path.join(ext_path, "localstack_ext")
        egg_path = os.path.join(ext_path, "localstack_ext.egg-info")

        volumes.append(
            {
                "volume": f"{os.path.normpath(ext_code_path)}:/code/localstack_ext",
                "nodeFilters": ["server:*", "agent:*"],
            }
        )

    volumes.append(
        {
            "volume": f"{os.path.normpath(egg_path)}:/code/egg_info",
            "nodeFilters": ["server:*", "agent:*"],
        }
    )

    if mount_moto:
        moto_path = os.path.join(root_path, "..", "moto", "moto")
        volumes.append(
            {"volume": f"{moto_path}:/code/moto", "nodeFilters": ["server:*", "agent:*"]}
        )

    config = {"apiVersion": "k3d.io/v1alpha3", "kind": "Simple", "volumes": volumes}

    if write_files:
        with open(os.path.join(os.getcwd(), "cluster-config.yaml"), "w") as f:
            f.write(yaml.dump(config))
            f.close()
            print(
                "Generated kubernetes cluster configuration file at kubernetes/cluster-config.yaml"
            )
    else:
        print("Generated kubernetes cluster configuration:")
        print("=====================================")
        print(yaml.dump(config))
        print("=====================================")
    return config


def snake_to_kebab_case(string: str):
    return string.lower().replace("_", "-")


def generate_k8s_cluster_overrides(
    pro: bool = False, cluster_config: dict = None, write_files: bool = False
):
    volumes = []
    for volume in cluster_config["volumes"]:
        volumes.append(
            {
                "name": snake_to_kebab_case(volume["volume"].split(":")[-1].split("/")[-1]),
                "hostPath": {"path": volume["volume"].split(":")[-1], "type": "Directory"},
            }
        )

    volumen_mounts = []
    target_path = "/opt/code/localstack/"
    venv_path = os.path.join(target_path, ".venv", "lib", "python3.11", "site-packages")
    for volume in volumes:
        if volume["name"] == "egg-info":
            volumen_mounts.append(
                {
                    "name": volume["name"],
                    "readOnly": True,
                    "mountPath": os.path.join(
                        target_path,
                        "localstack-ext.egg-info" if pro else "localstack_core.egg-info",
                    ),
                }
            )
            continue

        volumen_mounts.append(
            {
                "name": volume["name"],
                "readOnly": True,
                "mountPath": os.path.join(venv_path, volume["hostPath"]["path"].split("/")[-1]),
            }
        )

    overrides = {
        "volumes": volumes,
        "volumeMounts": volumen_mounts,
    }

    if write_files:
        with open(os.path.join(os.getcwd(), "cluster-overrides.yaml"), "w") as f:
            f.write(yaml.dump(overrides))
            f.close()
        print("Generated kubernetes cluster overrides file at kubernetes/cluster-overrides.yaml")
    else:
        print("Generated kubernetes cluster overrides:")
        print("=====================================")
        print(yaml.dump(overrides))
        print("=====================================")


@click.command("run")
@click.option(
    "--pro", is_flag=True, default=None, help="Mount the localstack-ext code into the cluster."
)
@click.option(
    "--mount-moto", is_flag=True, default=None, help="Mount the moto code into the cluster."
)
@click.option(
    "--write-files",
    is_flag=True,
    default=None,
    help="Write the configuration and overrides to files.",
)
@click.argument("command", nargs=-1, required=False)
def run(pro: bool = None, mount_moto: bool = False, write_files: bool = False, command: str = None):
    """
    A tool for localstack developers to generated the kubernetes cluster configuration file and the overrides to mount the localstack code into the cluster.
    """

    print(pro)

    config = generate_k8s_cluster_config(pro=pro, mount_moto=mount_moto, write_files=write_files)

    generate_k8s_cluster_overrides(pro, config, write_files=write_files)


def main():
    run()


if __name__ == "__main__":
    main()
