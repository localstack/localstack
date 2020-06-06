import base64

from moto.ses.responses import EmailResponse as email_responses
from moto.ses.exceptions import MessageRejectedError
from localstack import config
from localstack.utils.common import to_str
from localstack.services.infra import start_moto_server


def apply_patches():
    def get_source_from_raw(raw_data):
        entities = raw_data.split('\n')
        for entity in entities:
            if 'From: ' in entity:
                return entity.replace('From: ', '').strip()

        return None

    email_responses_send_raw_email_orig = email_responses.send_raw_email

    def email_responses_send_raw_email(self):
        (source, ) = self.querystring.get('Source', [''])
        if source.strip():
            return email_responses_send_raw_email_orig(self)

        raw_data = to_str(base64.b64decode(self.querystring.get('RawMessage.Data')[0]))

        source = get_source_from_raw(raw_data)
        if not source:
            raise MessageRejectedError('Source not specified')

        self.querystring['Source'] = [source]
        return email_responses_send_raw_email_orig(self)

    email_responses.send_raw_email = email_responses_send_raw_email


def start_ses(port=None, backend_port=None, asynchronous=None):
    port = port or config.PORT_SES
    apply_patches()
    return start_moto_server(
        key='ses',
        name='SES',
        port=port,
        backend_port=backend_port,
        asynchronous=asynchronous
    )
