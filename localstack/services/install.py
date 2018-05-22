#!/usr/bin/env python

import os
import sys
import glob
import shutil
import logging
import tempfile
from localstack.constants import (DEFAULT_SERVICE_PORTS, ELASTICMQ_JAR_URL, STS_JAR_URL,
    ELASTICSEARCH_JAR_URL, DYNAMODB_JAR_URL, LOCALSTACK_MAVEN_VERSION)
from localstack.utils.common import download, parallelize, run, mkdir, save_file, unzip, rm_rf, chmod_r

THIS_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.realpath(os.path.join(THIS_PATH, '..'))

INSTALL_DIR_INFRA = '%s/infra' % ROOT_PATH
INSTALL_DIR_NPM = '%s/node_modules' % ROOT_PATH
INSTALL_DIR_ES = '%s/elasticsearch' % INSTALL_DIR_INFRA
INSTALL_DIR_DDB = '%s/dynamodb' % INSTALL_DIR_INFRA
INSTALL_DIR_KCL = '%s/amazon-kinesis-client' % INSTALL_DIR_INFRA
INSTALL_DIR_ELASTICMQ = '%s/elasticmq' % INSTALL_DIR_INFRA
INSTALL_PATH_LOCALSTACK_FAT_JAR = '%s/localstack-utils-fat.jar' % INSTALL_DIR_INFRA
TMP_ARCHIVE_ES = os.path.join(tempfile.gettempdir(), 'localstack.es.zip')
TMP_ARCHIVE_DDB = os.path.join(tempfile.gettempdir(), 'localstack.ddb.zip')
TMP_ARCHIVE_STS = os.path.join(tempfile.gettempdir(), 'aws-java-sdk-sts.jar')
TMP_ARCHIVE_ELASTICMQ = os.path.join(tempfile.gettempdir(), 'elasticmq-server.jar')
URL_LOCALSTACK_FAT_JAR = ('http://central.maven.org/maven2/' +
    'cloud/localstack/localstack-utils/{v}/localstack-utils-{v}-fat.jar').format(v=LOCALSTACK_MAVEN_VERSION)

# set up logger
LOGGER = logging.getLogger(__name__)


def install_elasticsearch():
    if not os.path.exists(INSTALL_DIR_ES):
        LOGGER.info('Downloading and installing local Elasticsearch server. This may take some time.')
        mkdir(INSTALL_DIR_INFRA)
        # download and extract archive
        download_and_extract_with_retry(ELASTICSEARCH_JAR_URL, TMP_ARCHIVE_ES, INSTALL_DIR_INFRA)
        elasticsearch_dir = glob.glob(os.path.join(INSTALL_DIR_INFRA, 'elasticsearch*'))
        if not elasticsearch_dir:
            raise Exception('Unable to find Elasticsearch folder in %s' % INSTALL_DIR_INFRA)
        shutil.move(elasticsearch_dir[0], INSTALL_DIR_ES)

        for dir_name in ('data', 'logs', 'modules', 'plugins', 'config/scripts'):
            dir_path = '%s/%s' % (INSTALL_DIR_ES, dir_name)
            mkdir(dir_path)
            chmod_r(dir_path, 0o777)


def install_elasticmq():
    if not os.path.exists(INSTALL_DIR_ELASTICMQ):
        LOGGER.info('Downloading and installing local ElasticMQ server. This may take some time.')
        mkdir(INSTALL_DIR_ELASTICMQ)
        # download archive
        if not os.path.exists(TMP_ARCHIVE_ELASTICMQ):
            download(ELASTICMQ_JAR_URL, TMP_ARCHIVE_ELASTICMQ)
        shutil.copy(TMP_ARCHIVE_ELASTICMQ, INSTALL_DIR_ELASTICMQ)


def install_kinesalite():
    target_dir = '%s/kinesalite' % INSTALL_DIR_NPM
    if not os.path.exists(target_dir):
        LOGGER.info('Downloading and installing local Kinesis server. This may take some time.')
        run('cd "%s" && npm install' % ROOT_PATH)


def install_dynamodb_local():
    if not os.path.exists(INSTALL_DIR_DDB):
        LOGGER.info('Downloading and installing local DynamoDB server. This may take some time.')
        mkdir(INSTALL_DIR_DDB)
        # download and extract archive
        download_and_extract_with_retry(DYNAMODB_JAR_URL, TMP_ARCHIVE_DDB, INSTALL_DIR_DDB)

    # fix for Alpine, otherwise DynamoDBLocal fails with:
    # DynamoDBLocal_lib/libsqlite4java-linux-amd64.so: __memcpy_chk: symbol not found
    if is_alpine():
        ddb_libs_dir = '%s/DynamoDBLocal_lib' % INSTALL_DIR_DDB
        patched_marker = '%s/alpine_fix_applied' % ddb_libs_dir
        if not os.path.exists(patched_marker):
            patched_lib = ('https://rawgit.com/bhuisgen/docker-alpine/master/alpine-dynamodb/' +
                'rootfs/usr/local/dynamodb/DynamoDBLocal_lib/libsqlite4java-linux-amd64.so')
            patched_jar = ('https://rawgit.com/bhuisgen/docker-alpine/master/alpine-dynamodb/' +
                'rootfs/usr/local/dynamodb/DynamoDBLocal_lib/sqlite4java.jar')
            run("curl -L -o %s/libsqlite4java-linux-amd64.so '%s'" % (ddb_libs_dir, patched_lib))
            run("curl -L -o %s/sqlite4java.jar '%s'" % (ddb_libs_dir, patched_jar))
            save_file(patched_marker, '')

    # fix logging configuration for DynamoDBLocal
    log4j2_config = """<Configuration status="WARN">
      <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
          <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n"/>
        </Console>
      </Appenders>
      <Loggers>
        <Root level="WARN"><AppenderRef ref="Console"/></Root>
      </Loggers>
    </Configuration>"""
    log4j2_file = os.path.join(INSTALL_DIR_DDB, 'log4j2.xml')
    save_file(log4j2_file, log4j2_config)
    run('cd "%s" && zip -u DynamoDBLocal.jar log4j2.xml || true' % INSTALL_DIR_DDB)


def install_amazon_kinesis_client_libs():
    # install KCL/STS JAR files
    if not os.path.exists(INSTALL_DIR_KCL):
        mkdir(INSTALL_DIR_KCL)
        if not os.path.exists(TMP_ARCHIVE_STS):
            download(STS_JAR_URL, TMP_ARCHIVE_STS)
        shutil.copy(TMP_ARCHIVE_STS, INSTALL_DIR_KCL)
    # Compile Java files
    from localstack.utils.kinesis import kclipy_helper
    classpath = kclipy_helper.get_kcl_classpath()
    java_files = '%s/utils/kinesis/java/com/atlassian/*.java' % ROOT_PATH
    class_files = '%s/utils/kinesis/java/com/atlassian/*.class' % ROOT_PATH
    if not glob.glob(class_files):
        run('javac -cp "%s" %s' % (classpath, java_files))


def install_lambda_java_libs():
    # install LocalStack "fat" JAR file (contains all dependencies)
    if not os.path.exists(INSTALL_PATH_LOCALSTACK_FAT_JAR):
        LOGGER.info('Downloading and installing LocalStack Java libraries. This may take some time.')
        download(URL_LOCALSTACK_FAT_JAR, INSTALL_PATH_LOCALSTACK_FAT_JAR)


def install_component(name):
    if name == 'kinesis':
        install_kinesalite()
    elif name == 'dynamodb':
        install_dynamodb_local()
    elif name == 'es':
        install_elasticsearch()
    elif name == 'sqs':
        install_elasticmq()


def install_components(names):
    parallelize(install_component, names)
    install_lambda_java_libs()


def install_all_components():
    install_components(DEFAULT_SERVICE_PORTS.keys())


# -----------------
# HELPER FUNCTIONS
# -----------------


def is_alpine():
    try:
        run('cat /etc/issue | grep Alpine', print_error=False)
        return True
    except Exception:
        return False


def download_and_extract_with_retry(archive_url, tmp_archive, target_dir):

    def download_and_extract():
        if not os.path.exists(tmp_archive):
            download(archive_url, tmp_archive)
        unzip(tmp_archive, target_dir)

    try:
        download_and_extract()
    except Exception:
        # try deleting and re-downloading the zip file
        LOGGER.info('Unable to extract file, re-downloading ZIP archive: %s' % tmp_archive)
        rm_rf(tmp_archive)
        download_and_extract()


if __name__ == '__main__':

    if len(sys.argv) > 1:
        if sys.argv[1] == 'libs':
            print('Initializing installation.')
            logging.basicConfig(level=logging.INFO)
            logging.getLogger('requests').setLevel(logging.WARNING)
            install_all_components()
            print('Done.')
        elif sys.argv[1] == 'testlibs':
            # Install additional libraries for testing
            install_amazon_kinesis_client_libs()
