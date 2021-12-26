from localstack.services.infra import start_moto_server


def start_configservice(port=None, asynchronous=False):
    return start_moto_server("config", port, name="Config Service", asynchronous=asynchronous)
