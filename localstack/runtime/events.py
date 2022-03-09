import threading

infra_starting = threading.Event()
infra_ready = threading.Event()
infra_stopping = threading.Event()
infra_stopped = threading.Event()
