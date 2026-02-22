import json

from rolo import Request, route

from localstack.http import Response
from localstack.services.sts.jwt import public_key_to_jwk
from localstack.services.sts.models import sts_stores


class StsCustomEndpoints:
    @route("/_aws/sts/<account_id>/.well-known/jwks.json", methods=["GET"])
    def jwks(self, request: Request, account_id: str):
        store = sts_stores[account_id]["us-east-1"]
        keys = []
        if store.signing_key:
            keys.append(public_key_to_jwk(store.signing_key.public_key()))
        if store.ec_signing_key:
            keys.append(public_key_to_jwk(store.ec_signing_key.public_key()))
        return Response(json.dumps({"keys": keys}), content_type="application/json")
