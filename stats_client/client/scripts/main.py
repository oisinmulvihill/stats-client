# -*- coding: utf-8 -*-
"""
Oisin Mulvihill
2015-11-06

"""
import json
import logging
from optparse import OptionParser


from stats.analytics import Analytics


def get_log(e=None):
    return logging.getLogger("{0}.{1}".format(__name__, e) if e else __name__)


def logtoconsolefallback(log):
    # Log to console instead:
    hdlr = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s'
    )
    hdlr.setFormatter(formatter)
    log.addHandler(hdlr)
    log.setLevel(logging.DEBUG)
    log.propagate = False


def main():
    """
    """
    parser = OptionParser()

    parser.add_option(
        "--uid", action="store", dest="uid",
        default='test-id',
        help="The unique id string to tie events together (default: %default)."
    )

    parser.add_option(
        "--event", action="store", dest="event",
        default='test.hello_world',
        help="The event string e.g. %default."
    )

    parser.add_option(
        "--data", action="store", dest="data",
        default='{}',
        help="The JSON payload to send with the event e.g. %default."
    )

    parser.add_option(
        "--access_token", action="store", dest="access_token",
        default=None,
        help="The API access_token needed to talk to the stats-service."
    )

    parser.add_option(
        "--url", action="store", dest="url",
        default="http://127.0.0.1:20080",
        help="The URL of the stats-service (default: %default)."
    )

    (options, args) = parser.parse_args()

    log = logging.getLogger()

    logtoconsolefallback(log)

    if options.access_token is None:
        raise SystemExit("Please specify the --access_token to use.")

    Analytics.init(dict(
        url=options.url,
        access_token=options.access_token
    ))

    log.debug("uid: '{}'".format(options.uid))

    log.debug("json loads of: '{}'".format(options.data))
    data = json.loads(options.data)

    log.debug("event: '{}'".format(options.event))

    Analytics.log(
        uid=options.uid,
        event=options.event,
        data=data,
    )
