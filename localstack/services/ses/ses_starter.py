import base64

import logging
from moto.ses.responses import EmailResponse as email_responses
from moto.ses.exceptions import MessageRejectedError
from localstack import config
from localstack.utils.common import to_str
from localstack.services.infra import start_moto_server

LOGGER = logging.getLogger(__name__)


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

        LOGGER.debug('Raw email:\n%s' % raw_data)

        source = get_source_from_raw(raw_data)
        if not source:
            raise MessageRejectedError('Source not specified')

        self.querystring['Source'] = [source]
        return email_responses_send_raw_email_orig(self)

    email_responses.send_raw_email = email_responses_send_raw_email

    email_responses_send_email_orig = email_responses.send_email

    def email_responses_send_email(self):
        bodydatakey = 'Message.Body.Text.Data'
        if 'Message.Body.Html.Data' in self.querystring:
            bodydatakey = 'Message.Body.Html.Data'

        body = self.querystring.get(bodydatakey)[0]
        source = self.querystring.get('Source')[0]
        subject = self.querystring.get('Message.Subject.Data')[0]
        destinations = {'ToAddresses': [], 'CcAddresses': [], 'BccAddresses': []}
        for dest_type in destinations:
            # consume up to 51 to allow exception
            for i in range(1, 52):
                field = 'Destination.%s.member.%s' % (dest_type, i)
                address = self.querystring.get(field)
                if address is None:
                    break
                destinations[dest_type].append(address[0])

        LOGGER.debug('Raw email\nFrom: %s\nTo: %s\nSubject: %s\nBody:\n%s'
                     % (source, destinations, subject, body))

        return email_responses_send_email_orig(self)

    email_responses.send_email = email_responses_send_email


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
