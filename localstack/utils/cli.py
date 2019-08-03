import re
from docopt import docopt
from localstack import config
from localstack.utils import bootstrap

# Note: make sure we don't have imports at the root level here


def cmd_infra(argv, args):
    """
Usage:
  localstack infra <subcommand> [options]

Commands:
  infra start       Start the local infrastructure

Options:
  --docker          Run the infrastructure in a Docker container (default)
  --host            Run the infrastructure on the local host
    """
    if argv[0] == 'start':
        argv = ['infra', 'start'] + argv[1:]
        args['<command>'] = 'infra'
        args['<args>'] = ['start'] + args['<args>']
    args.update(docopt(cmd_infra.__doc__.strip(), argv=argv))
    if args['<subcommand>'] == 'start':
        if args['--docker'] and args['--host']:
            raise Exception('Please specify either --docker or --host')
        print('Starting local dev environment. CTRL-C to quit.')
        in_docker = args['--docker'] or not args['--host']
        if in_docker:
            bootstrap.start_infra_in_docker()
        else:
            bootstrap.start_infra_locally()


def cmd_web(argv, args):
    """
Usage:
  localstack web <subcommand> [options]

Commands:
  web start           Start the Web dashboard

Options:
  --port=<>           Network port for running the Web server (default: 8080)
    """
    if len(argv) <= 1 or argv[1] != 'start':
        argv = ['web', 'start'] + argv[1:]
        args['<args>'] = ['start'] + args['<args>']
    args.update(docopt(cmd_web.__doc__.strip(), argv=argv))
    if args['<subcommand>'] == 'start':
        import localstack.dashboard.api
        port = args['--port'] or config.PORT_WEB_UI
        localstack.dashboard.api.serve(port)


def cmd_ssh(argv, args):
    """
Usage:
  localstack ssh [options]

Commands:
  ssh               Obtain a shell in the running LocalStack container

Options:
    """
    bootstrap.bootstrap_installation()
    from localstack.utils.common import run

    args.update(docopt(cmd_ssh.__doc__.strip(), argv=argv))
    lines = run('docker ps').split('\n')[1:]
    lines = [l for l in lines if 'localstack' in l]
    if len(lines) != 1:
        raise Exception('Expected 1 running "localstack" container, but found %s' % len(lines))
    cid = re.split(r'\s', lines[0])[0]
    try:
        process = run('docker exec -it %s bash' % cid, tty=True)
        process.wait()
    except KeyboardInterrupt:
        pass
