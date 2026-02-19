import os


def handler(event, context):
    return {"environment": dict(os.environ)}
    # TODO: rework init env snapshotting test case because /proc/1 introspection does not work anymore at AWS
    # pid = event.get("pid")
    # with open(f"/proc/{pid}/environ", mode="rt") as f:
    #     environment = f.read()
    # environment = environment.split("\x00")
    # env_partition = [env.partition("=") for env in environment if env]
    # env_dict = {env[0]: env[2] for env in env_partition}
    # return {"environment": env_dict}
