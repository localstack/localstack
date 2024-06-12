import threading

# TODO: deprecate and replace access with ``get_current_runtime().starting``, ...
infra_starting = threading.Event()
infra_ready = threading.Event()
infra_stopping = threading.Event()
infra_stopped = threading.Event()
