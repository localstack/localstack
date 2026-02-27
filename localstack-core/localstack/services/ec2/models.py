from moto.ec2 import ec2_backends
from moto.ec2.models import EC2Backend


def get_ec2_backend(account_id: str, region: str) -> EC2Backend:
    return ec2_backends[account_id][region]
