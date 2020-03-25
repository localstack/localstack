#!/usr/bin/env python

import re
import os
import sys
import glob
import shutil
import logging
import tempfile
from localstack.utils import bootstrap
from localstack.constants import (DEFAULT_SERVICE_PORTS, ELASTICMQ_JAR_URL, STS_JAR_URL,
    ELASTICSEARCH_JAR_URL, ELASTICSEARCH_PLUGIN_LIST, ELASTICSEARCH_DELETE_MODULES,
    DYNAMODB_JAR_URL, DYNAMODB_JAR_URL_ALPINE, LOCALSTACK_MAVEN_VERSION, STEPFUNCTIONS_ZIP_URL,
    KMS_URL_PATTERN, LOCALSTACK_INFRA_PROCESS)
if __name__ == '__main__':
    bootstrap.bootstrap_installation()
# flake8: noqa: E402
from localstack.utils.common import (
    download, parallelize, run, mkdir, load_file, save_file, unzip, untar, rm_rf, chmod_r, is_alpine,
    in_docker, get_arch)

THIS_PATH = os.path.dirname(os.path.realpath(__file__))
ROOT_PATH = os.path.realpath(os.path.join(THIS_PATH, '..'))

INSTALL_DIR_INFRA = '%s/infra' % ROOT_PATH
INSTALL_DIR_NPM = '%s/node_modules' % ROOT_PATH
INSTALL_DIR_ES = '%s/elasticsearch' % INSTALL_DIR_INFRA
INSTALL_DIR_DDB = '%s/dynamodb' % INSTALL_DIR_INFRA
INSTALL_DIR_KCL = '%s/amazon-kinesis-client' % INSTALL_DIR_INFRA
INSTALL_DIR_STEPFUNCTIONS = '%s/stepfunctions' % INSTALL_DIR_INFRA
INSTALL_DIR_KMS = '%s/kms' % INSTALL_DIR_INFRA
INSTALL_DIR_ELASTICMQ = '%s/elasticmq' % INSTALL_DIR_INFRA
INSTALL_PATH_LOCALSTACK_FAT_JAR = '%s/localstack-utils-fat.jar' % INSTALL_DIR_INFRA
INSTALL_PATH_KMS_BINARY_PATTERN = os.path.join(INSTALL_DIR_KMS, 'local-kms.<arch>.bin')
URL_LOCALSTACK_FAT_JAR = ('https://repo1.maven.org/maven2/' +
    'cloud/localstack/localstack-utils/{v}/localstack-utils-{v}-fat.jar').format(v=LOCALSTACK_MAVEN_VERSION)

# Target version for javac, to ensure compatibility with earlier JREs
JAVAC_TARGET_VERSION = '1.8'

# As of 2019-10-09, the DDB fix (see below) doesn't seem to be required anymore
APPLY_DDB_ALPINE_FIX = False
# TODO: 2019-10-09: Temporarily overwriting DDB, as we're hitting a SIGSEGV JVM crash with the latest version
OVERWRITE_DDB_FILES_IN_DOCKER = False

# set up logger
LOGGER = logging.getLogger(__name__)


def install_elasticsearch():
    if not os.path.exists(INSTALL_DIR_ES):
        log_install_msg('Elasticsearch')
        mkdir(INSTALL_DIR_INFRA)
        # download and extract archive
        tmp_archive = os.path.join(tempfile.gettempdir(), 'localstack.es.tar.gz')
        download_and_extract_with_retry(ELASTICSEARCH_JAR_URL, tmp_archive, INSTALL_DIR_INFRA)
        elasticsearch_dir = glob.glob(os.path.join(INSTALL_DIR_INFRA, 'elasticsearch*'))
        if not elasticsearch_dir:
            raise Exception('Unable to find Elasticsearch folder in %s' % INSTALL_DIR_INFRA)
        shutil.move(elasticsearch_dir[0], INSTALL_DIR_ES)

        for dir_name in ('data', 'logs', 'modules', 'plugins', 'config/scripts'):
            dir_path = '%s/%s' % (INSTALL_DIR_ES, dir_name)
            mkdir(dir_path)
            chmod_r(dir_path, 0o777)

        # install default plugins
        for plugin in ELASTICSEARCH_PLUGIN_LIST:
            if is_alpine():
                # https://github.com/pires/docker-elasticsearch/issues/56
                os.environ['ES_TMPDIR'] = '/tmp'
            plugin_binary = os.path.join(INSTALL_DIR_ES, 'bin', 'elasticsearch-plugin')
            print('install elasticsearch-plugin %s' % (plugin))
            run('%s install -b  %s' % (plugin_binary, plugin))

    # delete some plugins to free up space
    for plugin in ELASTICSEARCH_DELETE_MODULES:
        module_dir = os.path.join(INSTALL_DIR_ES, 'modules', plugin)
        rm_rf(module_dir)

    # disable x-pack-ml plugin (not working on Alpine)
    xpack_dir = os.path.join(INSTALL_DIR_ES, 'modules', 'x-pack-ml', 'platform')
    rm_rf(xpack_dir)

    # patch JVM options file - replace hardcoded heap size settings
    jvm_options_file = os.path.join(INSTALL_DIR_ES, 'config', 'jvm.options')
    if os.path.exists(jvm_options_file):
        jvm_options = load_file(jvm_options_file)
        jvm_options_replaced = re.sub(r'(^-Xm[sx][a-zA-Z0-9\.]+$)', r'# \1', jvm_options, flags=re.MULTILINE)
        if jvm_options != jvm_options_replaced:
            save_file(jvm_options_file, jvm_options_replaced)


def install_elasticmq():
    if not os.path.exists(INSTALL_DIR_ELASTICMQ):
        log_install_msg('ElasticMQ')
        mkdir(INSTALL_DIR_ELASTICMQ)
        # download archive
        tmp_archive = os.path.join(tempfile.gettempdir(), 'elasticmq-server.jar')
        if not os.path.exists(tmp_archive):
            download(ELASTICMQ_JAR_URL, tmp_archive)
        shutil.copy(tmp_archive, INSTALL_DIR_ELASTICMQ)


def install_kinesalite():
    target_dir = '%s/kinesalite' % INSTALL_DIR_NPM
    if not os.path.exists(target_dir):
        log_install_msg('Kinesis')
        run('cd "%s" && npm install' % ROOT_PATH)


def install_local_kms():
    binary_path = INSTALL_PATH_KMS_BINARY_PATTERN.replace('<arch>', get_arch())
    if not os.path.exists(binary_path):
        log_install_msg('KMS')
        mkdir(INSTALL_DIR_KMS)
        kms_url = KMS_URL_PATTERN.replace('<arch>', get_arch())
        download(kms_url, binary_path)
        chmod_r(binary_path, 0o777)


def install_stepfunctions_local():
    if not os.path.exists(INSTALL_DIR_STEPFUNCTIONS):
        log_install_msg('Step Functions')
        tmp_archive = os.path.join(tempfile.gettempdir(), 'stepfunctions.zip')
        download_and_extract_with_retry(
            STEPFUNCTIONS_ZIP_URL, tmp_archive, INSTALL_DIR_STEPFUNCTIONS)


def install_dynamodb_local():
    if OVERWRITE_DDB_FILES_IN_DOCKER and in_docker():
        rm_rf(INSTALL_DIR_DDB)
    if not os.path.exists(INSTALL_DIR_DDB):
        log_install_msg('DynamoDB')
        # download and extract archive
        tmp_archive = os.path.join(tempfile.gettempdir(), 'localstack.ddb.zip')
        dynamodb_url = DYNAMODB_JAR_URL_ALPINE if in_docker() else DYNAMODB_JAR_URL
        download_and_extract_with_retry(dynamodb_url, tmp_archive, INSTALL_DIR_DDB)

    # fix for Alpine, otherwise DynamoDBLocal fails with:
    # DynamoDBLocal_lib/libsqlite4java-linux-amd64.so: __memcpy_chk: symbol not found
    if is_alpine():
        ddb_libs_dir = '%s/DynamoDBLocal_lib' % INSTALL_DIR_DDB
        patched_marker = '%s/alpine_fix_applied' % ddb_libs_dir
        if APPLY_DDB_ALPINE_FIX and not os.path.exists(patched_marker):
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
        tmp_archive = os.path.join(tempfile.gettempdir(), 'aws-java-sdk-sts.jar')
        if not os.path.exists(tmp_archive):
            download(STS_JAR_URL, tmp_archive)
        shutil.copy(tmp_archive, INSTALL_DIR_KCL)
    # Compile Java files
    from localstack.utils.kinesis import kclipy_helper
    classpath = kclipy_helper.get_kcl_classpath()
    java_files = '%s/utils/kinesis/java/cloud/localstack/*.java' % ROOT_PATH
    class_files = '%s/utils/kinesis/java/cloud/localstack/*.class' % ROOT_PATH
    if not glob.glob(class_files):
        run('javac -source %s -target %s -cp "%s" %s' % (
            JAVAC_TARGET_VERSION, JAVAC_TARGET_VERSION, classpath, java_files))


def install_lambda_java_libs():
    # install LocalStack "fat" JAR file (contains all dependencies)
    if not os.path.exists(INSTALL_PATH_LOCALSTACK_FAT_JAR):
        log_install_msg('LocalStack Java libraries', verbatim=True)
        download(URL_LOCALSTACK_FAT_JAR, INSTALL_PATH_LOCALSTACK_FAT_JAR)


def install_component(name):
    installers = {
        'kinesis': install_kinesalite,
        'dynamodb': install_dynamodb_local,
        'es': install_elasticsearch,
        'sqs': install_elasticmq,
        'stepfunctions': install_stepfunctions_local,
        'kms': install_local_kms
    }
    installer = installers.get(name)
    if installer:
        installer()


def install_components(names):
    parallelize(install_component, names)
    install_lambda_java_libs()


def install_all_components():
    # load plugins
    os.environ[LOCALSTACK_INFRA_PROCESS] = '1'
    bootstrap.load_plugins()
    # install all components
    install_components(DEFAULT_SERVICE_PORTS.keys())


# -----------------
# HELPER FUNCTIONS
# -----------------

def log_install_msg(component, verbatim=False):
    component = component if verbatim else 'local %s server' % component
    LOGGER.info('Downloading and installing %s. This may take some time.' % component)


def download_and_extract_with_retry(archive_url, tmp_archive, target_dir):
    mkdir(target_dir)

    def download_and_extract():
        if not os.path.exists(tmp_archive):
            download(archive_url, tmp_archive)

        _, ext = os.path.splitext(tmp_archive)
        if ext == '.zip':
            unzip(tmp_archive, target_dir)
        elif ext == '.gz' or ext == '.bz2':
            untar(tmp_archive, target_dir)
        else:
            raise Exception('Unsupported archive format: %s' % ext)

    try:
        download_and_extract()
    except Exception as e:
        # try deleting and re-downloading the zip file
        LOGGER.info('Unable to extract file, re-downloading ZIP archive %s: %s' % (tmp_archive, e))
        rm_rf(tmp_archive)
        download_and_extract()


if __name__ == '__main__':

    if len(sys.argv) > 1:
        if sys.argv[1] == 'libs':
            print('Initializing installation.')
            logging.basicConfig(level=logging.INFO)
            logging.getLogger('requests').setLevel(logging.WARNING)
            install_all_components()
        if sys.argv[1] in ('libs', 'testlibs'):
            # Install additional libraries for testing
            install_amazon_kinesis_client_libs()
        print('Done.')
