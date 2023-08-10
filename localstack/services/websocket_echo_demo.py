from localstack.http import route
from localstack.http.websocket import WebsocketRequest
from localstack.runtime import hooks


@route("/echo/<name>", methods=["WEBSOCKET"])
def echo_handler(request: WebsocketRequest, name: str):
    with request.accept() as ws:
        ws.send(f"thanks for connecting {name}")
        for line in iter(ws):
            ws.send(f"echo: {line}")
            if line == "exit":
                ws.send("ok bye!")
                break


@hooks.on_infra_start()
def add_websocket_demo_handler():
    from localstack.services.edge import ROUTER

    ROUTER.add(echo_handler)
