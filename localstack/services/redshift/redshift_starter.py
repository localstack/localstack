from moto.redshift import responses as redshift_responses

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.utils.common import recurse_object


def apply_patches():

    # patch itemize() to return proper XML response tags

    def itemize(data, parent_key=None, *args, **kwargs):
        # TODO: potentially add additional required tags here!
        list_parent_tags = ["ClusterSubnetGroups"]

        def fix_keys(o, **kwargs):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k in list_parent_tags:
                        if isinstance(v, dict) and "item" in v:
                            v[k[:-1]] = v.pop("item")
            return o

        result = itemize_orig(data, *args, **kwargs)
        recurse_object(result, fix_keys)
        return result

    itemize_orig = redshift_responses.itemize
    redshift_responses.itemize = itemize


def start_redshift(port=None, asynchronous=False):
    port = port or config.PORT_REDSHIFT
    apply_patches()
    return start_moto_server("redshift", port, name="Redshift", asynchronous=asynchronous)
