# Developer Guide

This document contains a few essential instructions for developing new features and bug fixes for *LocalStack*.

## General Application Architecture

The coarse-grained system architecture is illustrated in the figure below. The LocalStack components are
either installed on the local machine, or the entire application runs in a Docker container. The application
exposes a set of external network ports (see defaults in
[constants.py](https://github.com/localstack/localstack/blob/master/localstack/constants.py)).
Client applications can use the standard AWS SDKs to connect to LocalStack; most SDKs have a configuration
option to configure the endpoint URLs of the target services (e.g., configure `http://localhost:4572`
as endpoint URL to connect to local DynamoDB).

![architecture](architecture.png)

To handle incoming requests on the external network ports, LocalStack uses proxy threads which inspect
the incoming request message, forward the requests to corresponding backend service processes, and
perform any additional processing. The additional processing is required because some of the backend
services only provide the basic "CRUD" functionality for maintaining API state, and LocalStack
provides integrations on top of these services. This makes the backend services easily replaceable
with best-of-breed implementations.


## Proxy Interceptors

For the basic "CRUD" functionality of most services we're using a mock implementation (e.g., based on `moto`) in the background, and *LocalStack* adds a bunch of integrations on top of these services. We start up an HTTP proxy which intercepts all invocations and forwards requests to the backend. This allows us to add extended functionality without having to change the backend service.

The figure below illustrates the proxy mechanism and ports for the API Gateway service. (The default ports can be found in https://github.com/localstack/localstack/blob/master/localstack/constants.py )

```
 --------      -------------      -------------
| Client | -> |    Proxy    | -> |   Backend   |
|        |    | (port 4567) |    | (port 4566) |
 --------      -------------      -------------
```

The proxy follows a simple protocol by implementing 2 methods: `forward_request` which is called *before* a request is forwarded to the backend, and `return_response` which is called *after* a response has been received from the backend: https://github.com/localstack/localstack/blob/master/localstack/services/generic_proxy.py

The proxy implementation for API Gateway can be found here: https://github.com/localstack/localstack/blob/master/localstack/services/apigateway/apigateway_listener.py#L81

## Patching/Releasing a Third-Party Libraries

To enable a fast release cycle of *LocalStack*, we're using forked versions of various third-party libraries. For example, we have a forked version of `moto` which is published as a separate `moto-ext` pip package: https://github.com/whummer/moto/tree/localstack-fixes . If you decide to extend `moto`, you can either raise a PR against that repo, or against the main repo `spulec/moto` (then we need to take care of cross-merging and releasing new versions).

## Development Environment Setup Guide

#### Tools Required

* Python 3.7
* Sasl
* Pip
* Virtualenv
* OpenJDK
* Node & NPM
* Maven
* Gradle
* Terraform
* Docker
* Docker-Compose


#### Installation instructions

__Python 3.7+__

    update-alternatives --install /usr/bin/python python /usr/bin/python3.8 2

__Sasl__

    apt install libsasl2-dev

__Pip__

    apt-get install python3-pip
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 2

__Virtualenv__

    pip install virtualenv

__OpenJDK__

    apt-get install openjdk-11-jdk

__Node__

    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | bash
    curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -
    apt-get install -y nodejs

__Maven__

    wget https://mirrors.estointernet.in/apache/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip -O /opt/apache-maven-3.6.3-bin.zip
    unzip /opt/apache-maven-3.6.3-bin.zip -d /opt/

__Gradle__

    wget https://services.gradle.org/distributions/gradle-6.7-bin.zip -O /opt/gradle-6.7-bin.zip
    unzip /opt/gradle-6.7-bin.zip -d /opt/

__Terraform__

    curl -L -o /opt/terraform/terraform.zip https://releases.hashicorp.com/terraform/0.13.4/terraform_0.13.4_linux_amd64.zip
    (cd /opt/terraform && unzip -q /opt/terraform/terraform.zip && rm /opt/terraform/terraform.zip)

__Adding Environment variable__

    echo "PATH=$PATH:/opt/apache-maven-3.6.3/bin:/opt/gradle-6.7/bin:/opt/terraform" >> ~/.bashrc && source ~/.bashrc

__Docker__

    curl -sSLk https://get.docker.com | bash -

__Docker-Compose__

    sudo curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
