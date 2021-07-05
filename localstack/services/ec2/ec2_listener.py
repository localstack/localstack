import logging
import re

from localstack.services.generic_proxy import ProxyListener
from localstack.utils.common import to_str

LOG = logging.getLogger(__name__)


def fix_creation_date(method, path, response):
    try:
        content = to_str(response._content)
    except Exception:
        LOG.info("Unable to convert EC2 response to string: %s" % response._content)
        return
    response._content = re.sub(
        r">\s*([0-9-]+) ([0-9:.]+)Z?\s*</creationTimestamp>",
        r">\1T\2Z</creationTimestamp>",
        content,
        flags=re.DOTALL | re.MULTILINE,
    )
    response.headers["Content-Length"] = str(len(response._content))


def fix_error_tag(response):
    # fix error root element from moto
    response._content = re.sub(
        r"<(/?)ErrorResponse", r"<\1Response", to_str(response.content or "")
    )


class ProxyListenerEC2(ProxyListener):
    def return_response(self, method, path, data, headers, response):
        if response.content:
            fix_creation_date(method, path, response)
            fix_error_tag(response)


# instantiate listener
UPDATE_EC2 = ProxyListenerEC2()
