import random
import string

from localstack.utils.strings import long_uid, short_uid

USER_PROVIDED_IDS = {}


def get_custom_id(account_id, region, service, resource, name) -> str | None:
    # retrieves a custom_id for a resource. Returns None
    return USER_PROVIDED_IDS.get(".".join([account_id, region, service, resource, name]))


def set_custom_id(account_id, region, service, resource, name, custom_id):
    # sets a custom_id for a resource
    USER_PROVIDED_IDS[".".join([account_id, region, service, resource, name])] = custom_id


def unset_custom_id(account_id, region, service, resource, name):
    # removes a set custom_id for a resource
    USER_PROVIDED_IDS.pop(".".join([account_id, region, service, resource, name]), None)


def localstack_id(fn):
    # Decorator for helping in creation of static ids within localstack.
    def _wrapper(account_id, region, service, resource, name, **kwargs):
        if found_id := get_custom_id(account_id, region, service, resource, name):
            return found_id
        return fn(account_id, region, service, resource, name, **kwargs)

    return _wrapper


@localstack_id
def generate_uid(account_id, region, service, resource, name, length=16):
    return long_uid()[:length]


@localstack_id
def generate_short_uid(account_id, region, service, resource, name):
    return short_uid()


@localstack_id
def generate_str_id(account_id, region, service, resource, name, length=8):
    return "".join(random.choice(string.ascii_letters) for _ in range(length))
