"""
Wishlist:

- separate invoke sync/async path in provider (don't handle future in provider => agnostic)
- move helper fns out of lambda_service


Invoke Path

sync (RequestResponse)
provider => LambdaService => VersionManager => non-blocking query to CountingService for free concurrency => "invoke" => AssignmentService.get_environment (if no env available => PlacementService.create_environment) => send invocation (return future & block until result)

async (Event) => queueing / retry handler => sync
provider => LambdaService => VersionManager =>  LOCK or "lease invocation" from counting service [ blocking query in loop to CountingService for free concurrency | queue (only for event invoke) ] => "invoke"

Invoke FN1
Invoke FN2 ... signal FN1 assigned environment kill
Invoke FN1
Worker 1
"""



class LambdaService:
    """
    more or less equivalent to frontend invoke service + control plane service (background tasks, fn creation, lifecycle of assignment service, updates state in frontend service so it knows where to send an invoke request)

    * function version state management
    * management of version managers
    * Invoke
        alias routing TODO: test if routing is static for a single invocation? (retries for event invoke, do they take the same "path" for every retry?)

    """
    ...

class VersionManager:
    """
    depends on a "sub-view" of LambdaEnvironmentPlugin (e.g. some part of it with separate view, so that version managers don't interfere with each other)
        * get_environment() future
        * provision_environments(x) future
        * stop() ?

    keep track of state of a single version
        * provisioned state
        * deployment state (preparation before LambdaEnvironmentPlugin can take over)

    TODO: remove lambda_service reference in version manager
    TODO: don't manually manage provisioned state in version manager, but in plugin
    """

    state: VersionState | None
    provisioned_state: ProvisionedConcurrencyState | None




class LambdaEnvironmentPlugin:
    """
    1. "Assignment Service" ... routes invoke requests to available environments
        information about available, starting, failed, etc. environments
        "replaced the workermanagement service"
        stateful service

    2. "Placement Service" ... where and how to create execution environment

    first invoke of a fn => needs a new execution environment
    """
    ...

