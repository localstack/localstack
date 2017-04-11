#!/usr/bin/env python

import os
import sys
import logging
import __init__
from localstack.constants import DEFAULT_SERVICE_PORTS, ELASTICSEARCH_JAR_URL
from localstack.utils.common import parallelize, run


THIS_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.realpath(os.path.join(THIS_PATH, '..'))

INSTALL_DIR_INFRA = '%s/infra' % ROOT_PATH
INSTALL_DIR_NPM = '%s/node_modules' % ROOT_PATH
INSTALL_DIR_ES = '%s/elasticsearch' % INSTALL_DIR_INFRA
TMP_ARCHIVE_ES = '/tmp/localstack.es.zip'

# set up logger
LOGGER = logging.getLogger(os.path.basename(__file__))


def install_elasticsearch():
    if not os.path.exists(INSTALL_DIR_ES):
        LOGGER.info('Downloading and installing local Elasticsearch server. This may take some time.')
        run('mkdir -p %s' % INSTALL_DIR_INFRA)
        if not os.path.exists(TMP_ARCHIVE_ES):
            run('curl -o "%s" "%s"' % (TMP_ARCHIVE_ES, ELASTICSEARCH_JAR_URL))
        cmd = 'cd %s && cp %s es.zip && unzip -q es.zip && mv elasticsearch* elasticsearch && rm es.zip'
        run(cmd % (INSTALL_DIR_INFRA, TMP_ARCHIVE_ES))
        for dir_name in ('data', 'logs', 'modules', 'plugins', 'config/scripts'):
            cmd = 'cd %s && mkdir -p %s && chmod -R 777 %s'
            run(cmd % (INSTALL_DIR_ES, dir_name, dir_name))


def install_kinesalite():
    target_dir = '%s/kinesalite' % INSTALL_DIR_NPM
    if not os.path.exists(target_dir):
        LOGGER.info('Downloading and installing local Kinesis server. This may take some time.')
        run('cd "%s" && npm install kinesalite' % ROOT_PATH)


def install_dynalite():
    target_dir = '%s/dynalite' % INSTALL_DIR_NPM
    if not os.path.exists(target_dir):
        LOGGER.info('Downloading and installing local DynamoDB server. This may take some time.')
        run('cd "%s" && npm install dynalite' % ROOT_PATH)


def install_component(name):
    if name == 'kinesis':
        install_kinesalite()
    elif name == 'dynamodb':
        install_dynalite()
    elif name == 'es':
        install_elasticsearch()


def install_components(names):
    parallelize(install_component, names)


def install_all_components():
    install_components(DEFAULT_SERVICE_PORTS.keys())


if __name__ == '__main__':

    if len(sys.argv) > 1 and sys.argv[1] == 'run':
        print('Initializing installation.')
        logging.basicConfig(level=logging.INFO)
        install_all_components()
        print('Done.')
