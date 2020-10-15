import os
import json
from flask import Flask, render_template, jsonify, send_from_directory, request
from flask_swagger import swagger
from localstack import config
from localstack.utils import common
from localstack.services import generic_proxy, plugins
from localstack.services import infra as services_infra
from localstack.constants import VERSION, LOCALSTACK_WEB_PROCESS
from localstack.dashboard import infra
from localstack.utils.bootstrap import load_plugins, canonicalize_api_names
from localstack.utils.aws.aws_stack import Environment


root_path = os.path.dirname(os.path.realpath(__file__))
web_dir = root_path + '/web/'

app = Flask('app', template_folder=web_dir)
app.root_path = root_path


@app.route('/swagger.json')
def spec():
    swag = swagger(app)
    swag['info']['version'] = VERSION
    swag['info']['title'] = 'AWS Resources Dashboard'
    return jsonify(swag)


@app.route('/graph', methods=['POST'])
def get_graph():
    # TODO remove?
    """ Get deployment graph
        ---
        operationId: 'getGraph'
        parameters:
            - name: request
              in: body
    """
    data = get_payload()
    env = Environment.from_string(data.get('awsEnvironment'))
    graph = infra.get_graph(name_filter=data['nameFilter'], env=env, region=data.get('awsRegion'))
    return jsonify(graph)


@app.route('/services', methods=['GET'])
def get_status():
    """ Get status of deployed services
        ---
        operationId: 'getStatus'
    """
    result = services_infra.get_services_status()
    return jsonify(result)


@app.route('/services', methods=['POST'])
def set_status():
    """ Set status of deployed services
        ---
        operationId: 'setStatus'
    """
    data = get_payload()
    result = services_infra.set_service_status(data)
    return jsonify(result)


@app.route('/kinesis/<streamName>/<shardId>/events/latest', methods=['POST'])
def get_kinesis_events(streamName, shardId):
    """ Get latest events from Kinesis.
        ---
        operationId: 'getKinesisEvents'
        parameters:
            - name: streamName
              in: path
            - name: shardId
              in: path
            - name: request
              in: body
    """
    data = get_payload()
    env = Environment.from_string(data.get('awsEnvironment'))
    result = infra.get_kinesis_events(stream_name=streamName, shard_id=shardId, env=env)
    return jsonify(result)


@app.route('/lambda/<functionName>/code', methods=['POST'])
def get_lambda_code(functionName):
    """ Get source code for Lambda function.
        ---
        operationId: 'getLambdaCode'
        parameters:
            - name: functionName
              in: path
            - name: request
              in: body
    """
    data = get_payload()
    env = Environment.from_string(data.get('awsEnvironment'))
    result = infra.get_lambda_code(func_name=functionName, env=env)
    return jsonify(result)


@app.route('/health')
def get_health():
    # TODO: this should be moved into a separate service, once the dashboard UI is removed
    reload = request.args.get('reload') is not None
    result = plugins.get_services_health(reload=reload)
    return jsonify(result)


@app.route('/')
def hello():
    return render_template('index.html')


@app.route('/<path:path>')
def send_static(path):
    return send_from_directory(web_dir + '/', path)


def get_payload():
    return json.loads(common.to_str(request.data))


def ensure_webapp_installed():
    web_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), 'web'))
    node_modules_dir = os.path.join(web_dir, 'node_modules', 'jquery')
    if not os.path.exists(node_modules_dir):
        print('Initializing installation of Web application (this could take a long time, please be patient)')
        common.run('cd "%s"; npm install' % web_dir)


def serve(port):
    os.environ[LOCALSTACK_WEB_PROCESS] = '1'
    ensure_webapp_installed()
    load_plugins()
    canonicalize_api_names()

    backend_url = 'http://localhost:%s' % port
    services_infra.start_proxy(config.PORT_WEB_UI_SSL, backend_url, use_ssl=True)

    generic_proxy.serve_flask_app(app=app, port=port, quiet=True)
