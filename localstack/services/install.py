#!/usr/bin/env python

import re
import os
import sys
import glob
import time
import shutil
import logging
import tempfile
from localstack import config
from localstack.constants import MODULE_MAIN_PATH, INSTALL_DIR_INFRA
from localstack.utils.common import is_windows
from localstack.utils import bootstrap
from localstack.constants import (DEFAULT_SERVICE_PORTS, ELASTICMQ_JAR_URL, STS_JAR_URL,
    ELASTICSEARCH_URLS, ELASTICSEARCH_DEFAULT_VERSION, ELASTICSEARCH_PLUGIN_LIST,
    ELASTICSEARCH_DELETE_MODULES, DYNAMODB_JAR_URL, DYNAMODB_JAR_URL_ALPINE, LOCALSTACK_MAVEN_VERSION,
    STEPFUNCTIONS_ZIP_URL, KMS_URL_PATTERN, LOCALSTACK_INFRA_PROCESS)
if __name__ == '__main__':
    bootstrap.bootstrap_installation()
# flake8: noqa: E402
from localstack.utils.common import (
    download, parallelize, run, mkdir, load_file, save_file, unzip, untar, rm_rf,
    chmod_r, is_alpine, in_docker, get_arch, new_tmp_file)

INSTALL_DIR_NPM = '%s/node_modules' % MODULE_MAIN_PATH
INSTALL_DIR_DDB = '%s/dynamodb' % INSTALL_DIR_INFRA
INSTALL_DIR_KCL = '%s/amazon-kinesis-client' % INSTALL_DIR_INFRA
INSTALL_DIR_STEPFUNCTIONS = '%s/stepfunctions' % INSTALL_DIR_INFRA
INSTALL_DIR_KMS = '%s/kms' % INSTALL_DIR_INFRA
INSTALL_DIR_ELASTICMQ = '%s/elasticmq' % INSTALL_DIR_INFRA
INSTALL_PATH_LOCALSTACK_FAT_JAR = '%s/localstack-utils-fat.jar' % INSTALL_DIR_INFRA
INSTALL_PATH_DDB_JAR = os.path.join(INSTALL_DIR_DDB, 'DynamoDBLocal.jar')
INSTALL_PATH_KCL_JAR = os.path.join(INSTALL_DIR_KCL, 'aws-java-sdk-sts.jar')
INSTALL_PATH_STEPFUNCTIONS_JAR = os.path.join(INSTALL_DIR_STEPFUNCTIONS, 'StepFunctionsLocal.jar')
INSTALL_PATH_KMS_BINARY_PATTERN = os.path.join(INSTALL_DIR_KMS, 'local-kms.<arch>.bin')
INSTALL_PATH_ELASTICMQ_JAR = os.path.join(INSTALL_DIR_ELASTICMQ, 'elasticmq-server.jar')
INSTALL_PATH_KINESALITE_CLI = os.path.join(INSTALL_DIR_NPM, 'kinesalite', 'cli.js')
URL_LOCALSTACK_FAT_JAR = ('https://repo1.maven.org/maven2/' +
    'cloud/localstack/localstack-utils/{v}/localstack-utils-{v}-fat.jar').format(v=LOCALSTACK_MAVEN_VERSION)
MARKER_FILE_LIGHT_VERSION = '%s/.light-version' % INSTALL_DIR_INFRA
IMAGE_NAME_SFN_LOCAL = 'amazon/aws-stepfunctions-local'
ARTIFACTS_REPO = 'https://github.com/localstack/localstack-artifacts'
SFN_PATCH_CLASS = 'com/amazonaws/stepfunctions/local/runtime/executors/task/LambdaTaskStateExecutor.class'
SFN_PATCH_CLASS_URL = '%s/raw/master/stepfunctions-local-patch/%s' % (ARTIFACTS_REPO, SFN_PATCH_CLASS)

DEBUGPY_MODULE='debugpy'
DEBUGPY_DEPENDENCIES=['gcc', 'python3-dev', 'musl-dev']

# Target version for javac, to ensure compatibility with earlier JREs
JAVAC_TARGET_VERSION = '1.8'

# SQS backend implementation provider - either "moto" or "elasticmq"
SQS_BACKEND_IMPL = os.environ.get('SQS_PROVIDER') or 'moto'

# TODO: 2019-10-09: Temporarily overwriting DDB, as we're hitting a SIGSEGV JVM crash with the latest version
OVERWRITE_DDB_FILES_IN_DOCKER = False

# set up logger
LOG = logging.getLogger(__name__)


def get_elasticsearch_install_version(version=None):
    if config.SKIP_INFRA_DOWNLOADS:
        return ELASTICSEARCH_DEFAULT_VERSION
    return version or ELASTICSEARCH_DEFAULT_VERSION


def get_elasticsearch_install_dir(version=None):
    version = get_elasticsearch_install_version(version)
    if version == ELASTICSEARCH_DEFAULT_VERSION and not os.path.exists(MARKER_FILE_LIGHT_VERSION):
        # install the default version into a subfolder of the code base
        install_dir = os.path.join(INSTALL_DIR_INFRA, 'elasticsearch')
    else:
        install_dir = os.path.join(config.TMP_FOLDER, 'elasticsearch', version)
    return install_dir


def install_elasticsearch(version=None):
    version = get_elasticsearch_install_version(version)
    install_dir = get_elasticsearch_install_dir(version)
    installed_executable = os.path.join(install_dir, 'bin', 'elasticsearch')
    if not os.path.exists(installed_executable):
        log_install_msg('Elasticsearch (%s)' % version)
        es_url = ELASTICSEARCH_URLS.get(version)
        if not es_url:
            raise Exception('Unable to find download URL for Elasticsearch version "%s"' % version)
        install_dir_parent = os.path.dirname(install_dir)
        mkdir(install_dir_parent)
        # download and extract archive
        tmp_archive = os.path.join(config.TMP_FOLDER, 'localstack.%s' % os.path.basename(es_url))
        download_and_extract_with_retry(es_url, tmp_archive, install_dir_parent)
        elasticsearch_dir = glob.glob(os.path.join(install_dir_parent, 'elasticsearch*'))
        if not elasticsearch_dir:
            raise Exception('Unable to find Elasticsearch folder in %s' % install_dir_parent)
        shutil.move(elasticsearch_dir[0], install_dir)

        for dir_name in ('data', 'logs', 'modules', 'plugins', 'config/scripts'):
            dir_path = os.path.join(install_dir, dir_name)
            mkdir(dir_path)
            chmod_r(dir_path, 0o777)

        # install default plugins
        for plugin in ELASTICSEARCH_PLUGIN_LIST:
            if is_alpine():
                # https://github.com/pires/docker-elasticsearch/issues/56
                os.environ['ES_TMPDIR'] = '/tmp'
            plugin_binary = os.path.join(install_dir, 'bin', 'elasticsearch-plugin')
            plugin_dir = os.path.join(install_dir, 'plugins', plugin)
            if not os.path.exists(plugin_dir):
                LOG.info('Installing Elasticsearch plugin %s' % (plugin))
                run('%s install -b %s' % (plugin_binary, plugin))

    # delete some plugins to free up space
    for plugin in ELASTICSEARCH_DELETE_MODULES:
        module_dir = os.path.join(install_dir, 'modules', plugin)
        rm_rf(module_dir)

    # disable x-pack-ml plugin (not working on Alpine)
    xpack_dir = os.path.join(install_dir, 'modules', 'x-pack-ml', 'platform')
    rm_rf(xpack_dir)

    # patch JVM options file - replace hardcoded heap size settings
    jvm_options_file = os.path.join(install_dir, 'config', 'jvm.options')
    if os.path.exists(jvm_options_file):
        jvm_options = load_file(jvm_options_file)
        jvm_options_replaced = re.sub(r'(^-Xm[sx][a-zA-Z0-9\.]+$)', r'# \1', jvm_options, flags=re.MULTILINE)
        if jvm_options != jvm_options_replaced:
            save_file(jvm_options_file, jvm_options_replaced)


def install_elasticmq():
    if SQS_BACKEND_IMPL != 'elasticmq':
        return
    # TODO remove this function if we stop using ElasticMQ entirely
    if not os.path.exists(INSTALL_PATH_ELASTICMQ_JAR):
        log_install_msg('ElasticMQ')
        mkdir(INSTALL_DIR_ELASTICMQ)
        # download archive
        tmp_archive = os.path.join(config.TMP_FOLDER, 'elasticmq-server.jar')
        if not os.path.exists(tmp_archive):
            download(ELASTICMQ_JAR_URL, tmp_archive)
        shutil.copy(tmp_archive, INSTALL_DIR_ELASTICMQ)


def install_kinesalite():
    if not os.path.exists(INSTALL_PATH_KINESALITE_CLI):
        log_install_msg('Kinesis')
        run('cd "%s" && npm install' % MODULE_MAIN_PATH)


def install_local_kms():
    local_arch = get_arch()
    binary_path = INSTALL_PATH_KMS_BINARY_PATTERN.replace('<arch>', local_arch)
    if not os.path.exists(binary_path):
        log_install_msg('KMS')
        mkdir(INSTALL_DIR_KMS)
        kms_url = KMS_URL_PATTERN.replace('<arch>', local_arch)
        download(kms_url, binary_path)
        chmod_r(binary_path, 0o777)


def install_stepfunctions_local():
    if not os.path.exists(INSTALL_PATH_STEPFUNCTIONS_JAR):
        # pull the JAR file from the Docker image, which is more up-to-date than the downloadable JAR file
        log_install_msg('Step Functions')
        mkdir(INSTALL_DIR_STEPFUNCTIONS)
        run('{dc} pull {img}'.format(dc=config.DOCKER_CMD, img=IMAGE_NAME_SFN_LOCAL))
        docker_name = 'tmp-ls-sfn'
        run(('{dc} run --name={dn} --entrypoint= -d --rm {img} sleep 15').format(
                dc=config.DOCKER_CMD, dn=docker_name, img=IMAGE_NAME_SFN_LOCAL))
        time.sleep(5)
        run('{dc} cp {dn}:/home/stepfunctionslocal/ {tgt}'.format(dc=config.DOCKER_CMD,
            dn=docker_name, tgt=INSTALL_DIR_INFRA))
        run('mv %s/stepfunctionslocal/*.jar %s' % (INSTALL_DIR_INFRA, INSTALL_DIR_STEPFUNCTIONS))
        rm_rf('%s/stepfunctionslocal' % INSTALL_DIR_INFRA)
    # apply patches
    patch_class_file = os.path.join(INSTALL_DIR_STEPFUNCTIONS, SFN_PATCH_CLASS)
    if not os.path.exists(patch_class_file):
        download(SFN_PATCH_CLASS_URL, patch_class_file)
        cmd = 'cd "%s"; zip %s %s' % (INSTALL_DIR_STEPFUNCTIONS, INSTALL_PATH_STEPFUNCTIONS_JAR, SFN_PATCH_CLASS)
        run(cmd)




def install_dynamodb_local():
    if OVERWRITE_DDB_FILES_IN_DOCKER and in_docker():
        rm_rf(INSTALL_DIR_DDB)
    is_in_alpine = is_alpine()
    if not os.path.exists(INSTALL_PATH_DDB_JAR):
        log_install_msg('DynamoDB')
        # download and extract archive
        tmp_archive = os.path.join(tempfile.gettempdir(), 'localstack.ddb.zip')
        dynamodb_url = DYNAMODB_JAR_URL_ALPINE if is_in_alpine else DYNAMODB_JAR_URL
        download_and_extract_with_retry(dynamodb_url, tmp_archive, INSTALL_DIR_DDB)

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
    if not os.path.exists(INSTALL_PATH_KCL_JAR):
        mkdir(INSTALL_DIR_KCL)
        tmp_archive = os.path.join(tempfile.gettempdir(), 'aws-java-sdk-sts.jar')
        if not os.path.exists(tmp_archive):
            download(STS_JAR_URL, tmp_archive)
        shutil.copy(tmp_archive, INSTALL_DIR_KCL)
    # Compile Java files
    from localstack.utils.kinesis import kclipy_helper
    classpath = kclipy_helper.get_kcl_classpath()

    if is_windows():
        classpath = re.sub(r':([^\\])', r';\1', classpath)
    java_files = '%s/utils/kinesis/java/cloud/localstack/*.java' % MODULE_MAIN_PATH
    class_files = '%s/utils/kinesis/java/cloud/localstack/*.class' % MODULE_MAIN_PATH
    if not glob.glob(class_files):
        run('javac -source %s -target %s -cp "%s" %s' % (
            JAVAC_TARGET_VERSION, JAVAC_TARGET_VERSION, classpath, java_files))


def install_lambda_java_libs():
    # install LocalStack "fat" JAR file (contains all dependencies)
    if not os.path.exists(INSTALL_PATH_LOCALSTACK_FAT_JAR):
        log_install_msg('LocalStack Java libraries', verbatim=True)
        download(URL_LOCALSTACK_FAT_JAR, INSTALL_PATH_LOCALSTACK_FAT_JAR)


def install_cloudformation_libs():
    from localstack.services.cloudformation import deployment_utils
    # trigger download of CF module file
    deployment_utils.get_cfn_response_mod_file()


def install_component(name):
    installers = {
        'cloudformation': install_cloudformation_libs,
        'dynamodb': install_dynamodb_local,
        'kinesis': install_kinesalite,
        'kms': install_local_kms,
        'sqs': install_elasticmq,
        'stepfunctions': install_stepfunctions_local,
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

def install_debugpy_and_dependencies():
    try:
        import debugpy
    except ModuleNotFoundError:
        run('apk fetch %s --output %s'%  (' '.join(DEBUGPY_DEPENDENCIES), config.TMP_FOLDER))
        run('apk add %s --cache-dir %s' %  (' '.join(DEBUGPY_DEPENDENCIES), config.TMP_FOLDER ) )
        run('pip install %s' % DEBUGPY_MODULE )


# -----------------
# HELPER FUNCTIONS
# -----------------

def log_install_msg(component, verbatim=False):
    component = component if verbatim else 'local %s server' % component
    LOG.info('Downloading and installing %s. This may take some time.' % component)


def download_and_extract(archive_url, target_dir, retries=0, sleep=3, tmp_archive=None):
    mkdir(target_dir)

    tmp_archive = tmp_archive or new_tmp_file()
    if not os.path.exists(tmp_archive):
        # create temporary placeholder file, to avoid duplicate parallel downloads
        save_file(tmp_archive, '')
        for i in range(retries + 1):
            try:
                download(archive_url, tmp_archive)
                break
            except Exception:
                time.sleep(sleep)

    _, ext = os.path.splitext(tmp_archive)
    if ext == '.zip':
        unzip(tmp_archive, target_dir)
    elif ext == '.gz' or ext == '.bz2':
        untar(tmp_archive, target_dir)
    else:
        raise Exception('Unsupported archive format: %s' % ext)


def download_and_extract_with_retry(archive_url, tmp_archive, target_dir):
    try:
        download_and_extract(archive_url, target_dir, tmp_archive=tmp_archive)
    except Exception as e:
        # try deleting and re-downloading the zip file
        LOG.info('Unable to extract file, re-downloading ZIP archive %s: %s' % (tmp_archive, e))
        rm_rf(tmp_archive)
        download_and_extract(archive_url, target_dir, tmp_archive=tmp_archive)


if __name__ == '__main__':

    if len(sys.argv) > 1:
        os.environ['LOCALSTACK_API_KEY'] = os.environ.get('LOCALSTACK_API_KEY') or 'test'
        if sys.argv[1] == 'libs':
            print('Initializing installation.')
            logging.basicConfig(level=logging.INFO)
            logging.getLogger('requests').setLevel(logging.WARNING)
            install_all_components()
        if sys.argv[1] in ('libs', 'testlibs'):
            # Install additional libraries for testing
            install_amazon_kinesis_client_libs()
        print('Done.')
