
# CLOUD CONTROL
class ProgressEvent:
    ...

class ResourceRequest:
    request_token: str

    type_name: str
    identifier: str
    operation: str  # TODO: enum

    # progress event
    operation_status: str  # TODO: enum
    event_time: str
    status_message: str
    error_code: str


# CLOUDFORMATION

class Resource:
    logical_resource_id: str
    physical_resource_id: str
    properties: dict
    type_name: str


class StackEvent:
    ...


class Stack:
    status: str  # TODO

    template_original: str  # yaml or json
    template_processed: str # json (?)

    created_at: str
    updated_at: str

    events: list[StackEvent]

    resources: dict[str, Resource]




class ChangeSet:
    ...









# TODO
class StackSet:
    ...

class StackInstance:
    ...

