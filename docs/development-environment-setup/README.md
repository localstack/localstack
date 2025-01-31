# Development Environment Setup

Before you get started with contributing to LocalStack, make sure you’ve familiarized yourself with LocalStack from the perspective of a user.
You can follow our [getting started guide](https://docs.localstack.cloud/get-started/).
Once LocalStack runs in your Docker environment and you’ve played around with the LocalStack and `awslocal` CLI, you can move forward to set up your developer environment.

## Development requirements

You will need the following tools for the local development of LocalStack.

* [Python](https://www.python.org/downloads/) and `pip`
    * We recommend to use a Python version management tool like [`pyenv`](https://github.com/pyenv/pyenv/).
    This way you will always use the correct Python version as defined in `.python-version`.
* [Node.js & npm](https://nodejs.org/en/download/)
* [Docker](https://docs.docker.com/desktop/)

We recommend you to individually install the above tools using your favorite package manager.
For example, on macOS, you can use [Homebrew](https://brew.sh/) to install the above tools.

### Setting up the Development Environment

To make contributions to LocalStack, you need to be able to run LocalStack in host mode from your IDE, and be able to attach a debugger to the running LocalStack instance.
We have a basic tutorial to cover how you can do that.

The basic steps include:

1. Fork the localstack repository on GitHub [https://github.com/localstack/localstack/](https://github.com/localstack/localstack/)
2. Clone the forked localstack repository `git clone git@github.com:<GITHUB_USERNAME>/localstack.git`
3. Ensure you have `python`, `pip`, `node`, and `npm` installed.
> [!NOTE]
> You might also need `java` for some emulated services.
4. Install the Python dependencies using `make install`.
> [!NOTE]
> This will install the required pip dependencies in a local Python 3 `venv` directory called `.venv` (your global Python packages will remain untouched).
> Depending on your system, some `pip` modules may require additional native libs installed.

> [!NOTE]
> Consider running `make install-dev-types` to enable type hinting for efficient [integration tests](../testing/integration-tests/README.md) development.
5. Start localstack in host mode using `make start`

<div align="left">
      <a href="https://youtu.be/XHLBy6VKuCM">
         <img src="https://img.youtube.com/vi/XHLBy6VKuCM/0.jpg" style="width:100%;">
      </a>
</div>

### Building the Docker image for Development

We generally recommend using this command to build the `localstack/localstack` Docker image locally (works on Linux/macOS):

```bash
IMAGE_NAME="localstack/localstack" ./bin/docker-helper.sh build
```

### Additional Dependencies for running LocalStack in Host Mode

In host mode, additional dependencies (e.g., Java) are required for developing certain AWS-emulated services (e.g., DynamoDB).
The required dependencies vary depending on the service, [Configuration](https://docs.localstack.cloud/references/configuration/), operating system, and system architecture (i.e., x86 vs ARM).
Refer to our official [Dockerfile](https://github.com/localstack/localstack/blob/master/Dockerfile) and our [package installer LPM](Concepts/index.md#packages-and-installers) for more details.

#### Root Permissions

LocalStack runs its own [DNS server](https://docs.localstack.cloud/user-guide/tools/dns-server/) which listens for requests on port 53. This requires root permission. When LocalStack starts in host mode it runs the DNS server as sudo, so a prompt is triggered asking for the sudo password. This is annoying during local development, so to disable this functionality, use `DNS_ADDRESS=0`.

> [!NOTE]
> We don't recommend disabling the DNS server in general (e.g. in Docker) because the [DNS server](https://docs.localstack.cloud/user-guide/tools/dns-server/) enables seamless connectivity to LocalStack from different environments via the domain name `localhost.localstack.cloud`.


#### Python Dependencies

* [JPype1](https://pypi.org/project/JPype1/) might require `g++` to fix a compile error on ARM Linux `gcc: fatal error: cannot execute ‘cc1plus’`
  * Used in EventBridge, EventBridge Pipes, and Lambda Event Source Mapping for a Java-based event ruler via the opt-in configuration `EVENT_RULE_ENGINE=java`
  * Introduced in [#10615](https://github.com/localstack/localstack/pull/10615)

#### Test Dependencies

* Node.js is required for running LocalStack tests because the test fixture for CDK-based tests needs Node.js

#### DynamoDB

* [OpenJDK](https://openjdk.org/install/)

#### Kinesis

* [NodeJS & npm](https://nodejs.org/en/download/)

#### Lambda

* macOS users need to configure `LAMBDA_DEV_PORT_EXPOSE=1` such that the host can reach Lambda containers via IPv4 in bridge mode (see [#7367](https://github.com/localstack/localstack/pull/7367)).

### Changing our fork of moto

1. Fork our moto repository on GitHub [https://github.com/localstack/moto](https://github.com/localstack/moto)
2. Clone the forked moto repository `git clone git@github.com:<GITHUB_USERNAME>/moto.git` (using the `localstack` branch)
3. Within the localstack repository, install moto in **editable** mode:

```sh
# Assuming the following directory structure:
#.
#├── localstack
#└── moto

cd localstack
source .venv/bin/activate

pip install -e ../moto
```

### Tips

* If `virtualenv` chooses system python installations before your pyenv installations, manually initialize `virtualenv` before running `make install`: `virtualenv -p ~/.pyenv/shims/python3.10 .venv` .
* Terraform needs version <0.14 to work currently. Use [`tfenv`](https://github.com/tfutils/tfenv) to manage Terraform versions comfortable. Quick start: `tfenv install 0.13.7 && tfenv use 0.13.7`
* Set env variable `LS_LOG='trace'` to print every `http` request sent to localstack and their responses. It is useful for debugging certain issues.
* Catch linter or format errors early by installing Git pre-commit hooks via `pre-commit install`. [pre-commit](https://pre-commit.com/) installation: `pip install pre-commit` or `brew install pre-commit`.
