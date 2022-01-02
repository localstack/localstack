from localstack import config

PUBLISH_BATCH_TEMPLATE = """<PublishBatchResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
        <PublishBatchResult>
            <Successful>
            {% for resp in response["Successful"] %}
            <member>
                <Id>{{resp["Id"]}}</Id>
                <MessageId>{{resp["MessageId"]}}</MessageId>
                {% if resp["SequenceNumber"] %}
                    <SequenceNumber> {{resp["SequenceNumber"]}}</SequenceNumber>
                {% endif %}
            </member>
            {% endfor %}
            </Successful>
            <Failed>
            {% for resp in response["Failed"] %}
            <member>
                <Id>{{resp["Id"]}}</Id>
            </member>
            {% endfor %}
            </Failed>
        </PublishBatchResult>
        <ResponseMetadata>
            <RequestId>384ac68d-3775-11df-8963-01868b7c937a</RequestId>
        </ResponseMetadata>
    </PublishBatchResponse>"""


def start_sns(port=None, asynchronous=False, update_listener=None):
    from localstack.services.infra import start_moto_server

    port = port or config.PORT_SNS
    return start_moto_server(
        "sns",
        port,
        name="SNS",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
