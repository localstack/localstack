from moto.redshift import responses as redshift_responses

from localstack.aws.api.redshift import RedshiftApi
from localstack.utils.common import recurse_object
from localstack.utils.patch import patch


@patch(redshift_responses.itemize)
def itemize(fn, data, parent_key=None, *args, **kwargs):
    # TODO: potentially add additional required tags here!
    list_parent_tags = ["ClusterSubnetGroups"]

    def fix_keys(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in list_parent_tags:
                    if isinstance(v, dict) and "item" in v:
                        v[k[:-1]] = v.pop("item")
        return o

    result = fn(data, *args, **kwargs)
    recurse_object(result, fix_keys)
    return result


class RedshiftProvider(RedshiftApi):
    pass
