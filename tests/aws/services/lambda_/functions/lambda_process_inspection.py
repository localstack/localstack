def handler(event, context):
    pid = event.get("pid")
    with open(f"/proc/{pid}/environ", mode="rt") as f:
        environment = f.read()
    environment = environment.split("\x00")
    environment = [env.partition("=") for env in environment if env]
    environment = dict((env[0], env[2]) for env in environment)
    return {"environment": environment}
