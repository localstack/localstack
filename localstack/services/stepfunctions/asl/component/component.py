import abc


class Component(abc.ABC):
    def __str__(self):
        return f"({self.__class__.__name__}| {self.__dict__})"

    def __repr__(self):
        return self.__str__()
