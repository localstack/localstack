from rolo.gateway import Gateway

# look into localstack/aws/app.py

"""
We need to think about how to split the handlers. We can properly have the handlers for the different steps of an
API Gateway invocation.

Method Request -> Integration Request -> Integration -> Integration Response -> Method Response

But we need handlers earlier, to populate the context?
So we need a `parse_invocation_request`

We also need an exception handler to properly serialize the exception, and maybe swap them for GatewayResponse

This is where we can also plug some kind of `metrics` handler, devx handlers, etc?

TODO: we also need to think about Deployments. How do we freeze them? Do we just store them in the store? I think
we have no choice but to do that...
"""


class ApiGateway(Gateway):
    # TODO: not sure we need to extend it, might remove if not needed
    pass
