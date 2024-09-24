class LocalstackExit(Exception):
    """
    This exception can be raised during the startup procedure to terminate localstack with an exit code and
    a reason.
    """

    def __init__(self, reason: str = None, code: int = 0):
        super().__init__(reason)
        self.code = code
