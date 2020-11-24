# Development help and guideline

## How-to

### Starting LocalStack using Vagrant (Centos 8)
This is similar to `make docker-mount-run`, but instead of docker centos VM will be started and source code will be mounted inside.

#### Pre-requirements
- Vagrant
- `vagrant plugin install vagrant-vbguest`

#### Starting Vagrant
- `make vagant-start` (be ready to provide system password)

#### Using Vagrant
- `vagrant ssh`
- `sudo -s`
- `cd /localstack`
- `SERVICES=dynamodb DEBUG=1 make docker-mount-run`

#### Stopping Vagrant
- `make vagrant-stop` or `vagrant halt`

#### Deleting Vagrant VM
- `vagrant destroy`