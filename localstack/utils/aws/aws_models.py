import logging

LOG = logging.getLogger(__name__)


class Component:
    def __init__(self, id, env=None):
        self.id = id
        self.env = env
        self.created_at = None

    def name(self):
        return self.id

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "<%s:%s>" % (self.__class__.__name__, self.id)
