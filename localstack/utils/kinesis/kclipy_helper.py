#!/usr/bin/env python

import os
from glob import glob

from amazon_kclpy import kcl

from localstack.utils.aws import aws_stack
from localstack.utils.files import save_file


def get_dir_of_file(f):
    return os.path.dirname(os.path.abspath(f))


def get_kcl_dir():
    return get_dir_of_file(kcl.__file__)


def get_kcl_jar_path():
    jars = ":".join(glob(os.path.join(get_kcl_dir(), "jars", "*jar")))
    return jars


def get_kcl_classpath(properties=None, paths=None):
    """
    Generates a classpath that includes the location of the kcl jars, the
    properties file and the optional paths.

    :type properties: str
    :param properties: Path to properties file.

    :type paths: list
    :param paths: List of strings. The paths that will be prepended to the classpath.

    :rtype: str
    :return: A java class path that will allow your properties to be
             found and the MultiLangDaemon and its deps and
        any custom paths you provided.
    """
    if paths is None:
        paths = []
    # First make all the user provided paths absolute
    paths = [os.path.abspath(p) for p in paths]
    # We add our paths after the user provided paths because this permits users to
    # potentially inject stuff before our paths (otherwise our stuff would always
    # take precedence).
    paths.append(get_kcl_jar_path())
    if properties:
        # Add the dir that the props file is in
        dir_of_file = get_dir_of_file(properties)
        paths.append(dir_of_file)
    # add path of custom java code
    dir_name = os.path.dirname(os.path.realpath(__file__))
    paths.insert(0, os.path.realpath(os.path.join(dir_name, "java")))
    return ":".join([p for p in paths if p != ""])


def get_kcl_app_command(java, multi_lang_daemon_class, properties, paths=None):
    """
    Generates a command to run the MultiLangDaemon.

    :type java: str
    :param java: Path to java

    :type multi_lang_daemon_class: str
    :param multi_lang_daemon_class: Name of multi language daemon class, e.g.
            com.amazonaws.services.kinesis.multilang.MultiLangDaemon

    :type properties: str
    :param properties: Optional properties file to be included in the classpath.

    :type paths: list
    :param paths: List of strings. Additional paths to prepend to the classpath.

    :rtype: str
    :return: A command that will run the MultiLangDaemon with your
             properties and custom paths and java.
    """
    if paths is None:
        paths = []
    logging_config = os.path.join(get_dir_of_file(__file__), "java", "logging.properties")
    sys_props = f'-Djava.util.logging.config.file="{logging_config}" -Daws.cborEnabled=false'
    return "{java} -cp {cp} {sys_props} {daemon} {props}".format(
        java=java,
        cp=get_kcl_classpath(properties, paths),
        daemon=multi_lang_daemon_class,
        # Just need the basename because the path is added to the classpath
        props=os.path.basename(properties),
        sys_props=sys_props,
    )


def create_config_file(
    config_file,
    executableName,
    streamName,
    applicationName,
    credentialsProvider=None,
    region_name=None,
    **kwargs,
):
    if not credentialsProvider:
        credentialsProvider = "DefaultAWSCredentialsProviderChain"
    region_name = region_name or aws_stack.get_region()
    content = f"""
        executableName = {executableName}
        streamName = {streamName}
        applicationName = {applicationName}
        AWSCredentialsProvider = {credentialsProvider}
        kinesisCredentialsProvider = {credentialsProvider}
        dynamoDBCredentialsProvider = {credentialsProvider}
        cloudWatchCredentialsProvider = {credentialsProvider}
        processingLanguage = python/3.10
        shardSyncIntervalMillis = 2000
        parentShardPollIntervalMillis = 2000
        idleTimeBetweenReadsInMillis = 1000
        timeoutInSeconds = 60
        regionName = {region_name}
    """
    # optional properties
    for key, value in kwargs.items():
        content += f"\n{key} = {value}"
    content = content.replace("    ", "")
    save_file(config_file, content)
