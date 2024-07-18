from localstack.services.lambda_.event_source_mapping.pipe_loggers.pipe_logger import PipeLogger


class NoOpsPipeLogger(PipeLogger):
    def __init__(self):
        super().__init__(log_configuration={})

    def log_msg(self, message: dict) -> None:
        # intentionally logs nothing
        pass

    def log(self, logLevel: str, **kwargs):
        # intentionally logs nothing
        pass
