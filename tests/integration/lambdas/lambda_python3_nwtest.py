# simple test function that identifies the network it is running on
# note: this requires a web server on the local docker network which will
# with the alias "networkidentifier" that respond to the endpoingt /network.txt
#
# The makefile will set this up before running this test

import requests


def handler(event, context):
    r = requests.get('http://networkidentifier/network.txt')
    event['network'] = r.text
    return event
