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


def reserve_cidr_block(self, subnet_id: str, cidr_block: str):
    subnet = self.get_subnet(subnet_id)
    if not subnet:
        raise ValueError(f"Subnet with ID {subnet_id} not found")
    if not subnet.cidr_block:
        raise ValueError(f"Subnet with ID {subnet_id} does not have a CIDR block")
    if cidr_block in subnet.reserved_cidr_blocks:
        raise ValueError(f"CIDR block {cidr_block} is already reserved in subnet {subnet_id}")
    subnet.reserved_cidr_blocks.append(cidr_block)
    return {"SubnetId": subnet_id, "CidrBlock": cidr_block}


Subnet.reserve_cidr_block = reserve_cidr_block
