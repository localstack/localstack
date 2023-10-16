def get_moto_server_port():
    # TODO: deprecated, remove
    from localstack.services import motoserver

    return motoserver.get_moto_server().port
