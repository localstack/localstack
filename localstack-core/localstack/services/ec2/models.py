from moto.ec2 import ec2_backends
from moto.ec2.models import EC2Backend
from moto.ec2.models.subnets import Subnet


def get_ec2_backend(account_id: str, region: str) -> EC2Backend:
    return ec2_backends[account_id][region]


#
# Pickle patches
#


def set_state(self, state):
    state["_subnet_ip_generator"] = state["cidr"].hosts()
    self.__dict__.update(state)


def get_state(self):
    state = self.__dict__.copy()
    state.pop("_subnet_ip_generator", None)
    return state


Subnet.__setstate__ = set_state
Subnet.__getstate__ = get_state
