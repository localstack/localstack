import abc


class Component(abc.ABC):
    # TODO.
    def __str__(self):
        return str(self.__dict__)

    # TODO.
    def __repr__(self):
        return self.__str__()
