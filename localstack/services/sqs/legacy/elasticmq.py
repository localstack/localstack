import logging
import os

from localstack import config
from localstack.services import install
from localstack.utils.common import (
    TMP_FILES,
    TMP_THREADS,
    ShellCommandThread,
    get_free_tcp_port,
    save_file,
    short_uid,
)
from localstack.utils.run import FuncThread
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)

config_template = """
include classpath("application.conf")
node-address {
    protocol = http
    host = "%s"
    port = %s
    context-path = ""
}
rest-stats {
    enabled = false
    bind-port = 9325
    bind-hostname = "0.0.0.0"
}
rest-sqs {
    enabled = true
    bind-port = %s
    bind-hostname = "0.0.0.0"
    sqs-limits = strict
}
"""


class ElasticMQSerer(Server):
    max_heap_size: str = "256m"
    install_dir: str = install.INSTALL_DIR_ELASTICMQ

    def do_start_thread(self) -> FuncThread:
        install.install_elasticmq()
        # create config file
        config_params = config_template % (
            config.LOCALSTACK_HOSTNAME,
            get_free_tcp_port(),
            self.port,
        )

        # create temporary config
        config_file = os.path.join(config.dirs.tmp, "sqs.%s.conf" % short_uid())
        LOG.debug("saving config file to %s:\n%s", config_file, config_params)
        TMP_FILES.append(config_file)
        save_file(config_file, config_params)

        # start process
        cmd = [
            "java",
            f"-Dconfig.file={config_file}",
            f"-Xmx{self.max_heap_size}",
            "-jar",
            os.path.join(self.install_dir, "elasticmq-server.jar"),
        ]

        LOG.debug("starting elasticmq server with command %s", " ".join(cmd))
        t = ShellCommandThread(
            cmd,
            strip_color=True,
            log_listener=self._log_listener,
            auto_restart=True,
        )
        TMP_THREADS.append(t)
        t.start()
        return t

    def _log_listener(self, line, **_kwargs):
        LOG.info(line.rstrip())
