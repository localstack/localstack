import json
import socket
import traceback
import logging
import inspect
from localstack.utils.common import FuncThread, truncate

# set up local logger
LOGGER = logging.getLogger(__name__)


class EventFileReaderThread(FuncThread):
    def __init__(self, events_file, callback, ready_mutex=None):
        FuncThread.__init__(self, self.retrieve_loop, None)
        self.running = True
        self.events_file = events_file
        self.callback = callback
        self.ready_mutex = ready_mutex

    def retrieve_loop(self, params):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.events_file)
        sock.listen(1)
        if self.ready_mutex:
            self.ready_mutex.release()
        while self.running:
            try:
                conn, client_addr = sock.accept()
                thread = FuncThread(self.handle_connection, conn)
                thread.start()
            except Exception, e:
                LOGGER.error('Error dispatching client request: %s %s' % (e, traceback.format_exc()))
        sock.close()

    def handle_connection(self, conn):
        socket_file = conn.makefile()
        while self.running:
            line = socket_file.readline()[:-1]
            if line == '':
                # end of socket input stream
                break
            else:
                try:
                    event = json.loads(line)
                    records = event['records']
                    shard_id = event['shard_id']
                    method_args = inspect.getargspec(self.callback)[0]
                    if len(method_args) > 1:
                        self.callback(records, shard_id=shard_id)
                    else:
                        self.callback(records)
                except Exception, e:
                    LOGGER.warning("Unable to process JSON line: '%s': %s. Callback: %s" %
                        (truncate(line), traceback.format_exc(), self.callback))
        conn.close()

    def stop(self, quiet=True):
        self.running = False
