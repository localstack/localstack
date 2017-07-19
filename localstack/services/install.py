#!/usr/bin/env python

import os
import sys
import glob
import shutil
import logging
from localstack.constants import DEFAULT_SERVICE_PORTS, ELASTICSEARCH_JAR_URL, DYNAMODB_JAR_URL
from localstack.config import *
from localstack.utils.common import download, parallelize, run, mkdir

THIS_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.realpath(os.path.join(THIS_PATH, '..'))

INSTALL_DIR_INFRA = '%s/infra' % ROOT_PATH
INSTALL_DIR_NPM = '%s/node_modules' % ROOT_PATH
INSTALL_DIR_ES = '%s/elasticsearch' % INSTALL_DIR_INFRA
INSTALL_DIR_DDB = '%s/dynamodb' % INSTALL_DIR_INFRA
INSTALL_DIR_KCL = '%s/amazon-kinesis-client' % INSTALL_DIR_INFRA
INSTALL_PATH_LOCALSTACK_JAR = '%s/localstack-utils.jar' % INSTALL_DIR_INFRA
TMP_ARCHIVE_ES = os.path.join(tempfile.gettempdir(), 'localstack.es.zip')
TMP_ARCHIVE_DDB = os.path.join(tempfile.gettempdir(), 'localstack.ddb.zip')
TMP_ARCHIVE_STS = os.path.join(tempfile.gettempdir(), 'aws-java-sdk-sts.jar')
URL_STS_JAR = 'http://central.maven.org/maven2/com/amazonaws/aws-java-sdk-sts/1.11.14/aws-java-sdk-sts-1.11.14.jar'
URL_LOCALSTACK_JAR = ('https://github.com/localstack/localstack/raw/mvn/release/' +
    'com/atlassian/localstack-utils/1.0-SNAPSHOT/localstack-utils-1.0-SNAPSHOT.jar')

# list of additional pip packages to install
EXTENDED_PIP_LIBS = ['amazon-kclpy==1.4.5']

# set up logger
LOGGER = logging.getLogger(os.path.basename(__file__))


def install_elasticsearch():
    if not os.path.exists(INSTALL_DIR_ES):
        LOGGER.info('Downloading and installing local Elasticsearch server. This may take some time.')
        run('mkdir -p %s' % INSTALL_DIR_INFRA)
        if not os.path.exists(TMP_ARCHIVE_ES):
            download(ELASTICSEARCH_JAR_URL, TMP_ARCHIVE_ES)
        cmd = 'cd %s && cp %s es.zip && unzip -q es.zip && mv elasticsearch* elasticsearch && rm es.zip'
        run(cmd % (INSTALL_DIR_INFRA, TMP_ARCHIVE_ES))
        for dir_name in ('data', 'logs', 'modules', 'plugins', 'config/scripts'):
            cmd = 'cd %s && mkdir -p %s && chmod -R 777 %s'
            run(cmd % (INSTALL_DIR_ES, dir_name, dir_name))


def install_kinesalite():
    target_dir = '%s/kinesalite' % INSTALL_DIR_NPM
    if not os.path.exists(target_dir):
        LOGGER.info('Downloading and installing local Kinesis server. This may take some time.')
        run('cd "%s" && npm install' % ROOT_PATH)


def is_alpine():
    try:
        run('cat /etc/issue | grep Alpine', print_error=False)
        return True
    except Exception as e:
        return False


def install_dynamodb_local():
    if not os.path.exists(INSTALL_DIR_DDB):
        LOGGER.info('Downloading and installing local DynamoDB server. This may take some time.')
        mkdir(INSTALL_DIR_DDB)
        if not os.path.exists(TMP_ARCHIVE_DDB):
            download(DYNAMODB_JAR_URL, TMP_ARCHIVE_DDB)
        cmd = 'cd %s && cp %s ddb.zip && unzip -q ddb.zip && rm ddb.zip'
        run(cmd % (INSTALL_DIR_DDB, TMP_ARCHIVE_DDB))
        # fix for Alpine, otherwise DynamoDBLocal fails with:
        # DynamoDBLocal_lib/libsqlite4java-linux-amd64.so: __memcpy_chk: symbol not found
        if is_alpine():
            patched_lib = ('https://rawgit.com/bhuisgen/docker-alpine/master/alpine-dynamodb/' +
                'rootfs/usr/local/dynamodb/DynamoDBLocal_lib/libsqlite4java-linux-amd64.so')
            patched_jar = ('https://rawgit.com/bhuisgen/docker-alpine/master/alpine-dynamodb/' +
                'rootfs/usr/local/dynamodb/DynamoDBLocal_lib/sqlite4java.jar')
            run("curl -L -o %s/DynamoDBLocal_lib/libsqlite4java-linux-amd64.so '%s'" % (INSTALL_DIR_DDB, patched_lib))
            run("curl -L -o %s/DynamoDBLocal_lib/sqlite4java.jar '%s'" % (INSTALL_DIR_DDB, patched_jar))


def install_amazon_kinesis_libs():
    # install KCL/STS JAR files
    if not os.path.exists(INSTALL_DIR_KCL):
        mkdir(INSTALL_DIR_KCL)
        if not os.path.exists(TMP_ARCHIVE_STS):
            download(URL_STS_JAR, TMP_ARCHIVE_STS)
        shutil.copy(TMP_ARCHIVE_STS, INSTALL_DIR_KCL)
    # install LocalStack JAR file
    if not os.path.exists(INSTALL_PATH_LOCALSTACK_JAR):
        download(URL_LOCALSTACK_JAR, INSTALL_PATH_LOCALSTACK_JAR)
    # install extended libs
    try:
        from amazon_kclpy import kcl
    except Exception as e:
        for lib in EXTENDED_PIP_LIBS:
            run('pip install %s' % lib)
    # Compile Java files
    from localstack.utils.kinesis import kclipy_helper
    classpath = kclipy_helper.get_kcl_classpath()
    java_files = '%s/utils/kinesis/java/com/atlassian/*.java' % ROOT_PATH
    class_files = '%s/utils/kinesis/java/com/atlassian/*.class' % ROOT_PATH
    if not glob.glob(class_files):
        run('javac -cp "%s" %s' % (classpath, java_files))
    ext_java_dir = '%s/ext/java' % ROOT_PATH
    if not glob.glob('%s/target/*.jar' % ext_java_dir):
        run('cd "%s"; mvn -DskipTests package' % (ext_java_dir))


def install_component(name):
    if name == 'kinesis':
        install_kinesalite()
    elif name == 'dynamodb':
        install_dynamodb_local()
    elif name == 'es':
        install_elasticsearch()


def install_components(names):
    parallelize(install_component, names)
    install_amazon_kinesis_libs()


def install_all_components():
    install_components(DEFAULT_SERVICE_PORTS.keys())


if __name__ == '__main__':

    if len(sys.argv) > 1 and sys.argv[1] == 'run':
        print('Initializing installation.')
        logging.basicConfig(level=logging.INFO)
        install_all_components()
        print('Done.')
