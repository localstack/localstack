from flask import Flask, render_template, jsonify, send_from_directory, request
from flask_swagger import swagger
import os
import infra
import json

root_path = os.path.dirname(os.path.realpath(__file__))
web_dir = root_path + '/web/'

app = Flask('app', template_folder=web_dir)
app.root_path = root_path


@app.route('/swagger.json')
def spec():
    swag = swagger(app)
    swag['info']['version'] = "0.1"
    swag['info']['title'] = "C360 API"
    return jsonify(swag)


@app.route('/graph', methods=['POST'])
def get_graph():
    """ Get deployment graph
        ---
        operationId: 'getGraph'
        parameters:
            - name: 'request'
              in: body
    """
    data = json.loads(request.data)
    graph = infra.get_graph(name_filter=data['nameFilter'])
    return jsonify(graph)


@app.route('/kinesis/<streamName>/<shardId>/events/latest', methods=['GET'])
def get_kinesis_events(streamName, shardId):
    """ Get latest events from Kinesis.
        ---
        operationId: 'getKinesisEvents'
        parameters:
            - name: streamName
              in: path
            - name: shardId
              in: path
    """
    result = infra.get_kinesis_events(stream_name=streamName, shard_id=shardId)
    return jsonify(result)


@app.route('/lambda/<functionName>/code', methods=['GET'])
def get_lambda_code(functionName):
    """ Get source code for Lambda function.
        ---
        operationId: 'getLambdaCode'
        parameters:
            - name: functionName
              in: path
    """
    result = infra.get_lambda_code(func_name=functionName)
    return jsonify(result)


@app.route('/')
def hello():
    return render_template('index.html')


@app.route('/<path:path>')
def send_static(path):
    return send_from_directory(web_dir + '/', path)


def serve(port):
    app.run(port=int(port), debug=True, threaded=True, host='0.0.0.0')
