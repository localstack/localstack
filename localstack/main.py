#!/usr/bin/env python

"""
Main script for starting components.

Usage:
  main.py web [ --port=<port> ]
  main.py (-h | --help)

Options:
  -h --help     Show this screen.

"""

from docopt import docopt

DEFAULT_PORT = 8000

if __name__ == "__main__":
    args = docopt(__doc__)
    if args['web']:
        import dashboard.api
        port = args['--port'] or DEFAULT_PORT
        dashboard.api.serve(port)
