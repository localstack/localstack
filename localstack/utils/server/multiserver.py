from localstack.services import motoserver


def get_moto_server_port():
    # TODO: deprecated, remove
    return motoserver.get_moto_server().port
