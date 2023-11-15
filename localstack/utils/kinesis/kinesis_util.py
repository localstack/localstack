import json
import logging
import socket
import threading
import traceback
from typing import Any, Callable

from localstack.utils.strings import truncate
from localstack.utils.threads import FuncThread

# set up logger
LOG = logging.getLogger(__name__)


class EventFileReaderThread(FuncThread):
    def __init__(self, events_file, callback: Callable[[list], Any]):
        FuncThread.__init__(
            self, self.retrieve_loop, None, name="kinesis-event-file-reader", on_stop=self._on_stop
        )
        self.events_file = events_file
        self.callback = callback
        self.is_ready = threading.Event()
        self.sock = None

    def retrieve_loop(self, params):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.events_file)
        self.sock.listen(1)
        self.is_ready.set()
        with self.sock as sock:
            while self.running:
                try:
                    conn, client_addr = sock.accept()
                    if not self.running:
                        return
                    thread = FuncThread(
                        self.handle_connection,
                        conn,
                        name="kinesis-event-file-reader-connectionhandler",
                    )
                    thread.start()
                except Exception as e:
                    LOG.error("Error dispatching client request: %s %s", e, traceback.format_exc())

    def wait_for_ready(self):
        self.is_ready.wait()

    def _on_stop(self, *args, **kwargs):
        if self.sock:
            self.sock.close()

    def handle_connection(self, conn: socket):
        socket_file = conn.makefile()
        with socket_file as sock:
            while self.running:
                line = ""
                try:
                    line = sock.readline()
                    line = line.strip()
                    if not line:
                        # end of socket input stream
                        break
                    event = json.loads(line)
                    records = event["records"]
                    self.callback(records)
                except Exception as e:
                    LOG.warning(
                        "Unable to process JSON line: '%s': %s %s. Callback: %s",
                        truncate(line),
                        e,
                        traceback.format_exc(),
                        self.callback,
                    )
