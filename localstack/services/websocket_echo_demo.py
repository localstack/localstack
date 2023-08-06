from localstack.http import route
from localstack.http.websocket import WebsocketRequest
from localstack.runtime import hooks


@route("/echo/<name>", methods=["WEBSOCKET"])
def echo_handler(request: WebsocketRequest, name: str):
    request.handshake()

    request.send(f"thanks for connecting {name}")
    for line in request.iter_decoded():
        request.send(f"echo: {line}")
        if line == "exit":
            request.send("ok bye!")
            request.close()
            return


@hooks.on_infra_start()
def add_websocket_demo_handler():
    from localstack.services.edge import ROUTER

    ROUTER.add(echo_handler)
