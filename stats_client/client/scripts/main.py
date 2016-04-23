# -*- coding: utf-8 -*-
"""
Oisin Mulvihill
2015-11-06

"""
import sys
import json
import logging
from optparse import OptionParser


from stats_client.client.analytics import Analytics


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
        "--ping", action="store_true", dest="ping_check",
        default=False,
        help="Test the connection to the server by accessing /ping"
    )

    parser.add_option(
        "--get", action="store", dest="entry_id",
        default=None,
        help="Recover a specific event based on its ID."
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

    log = get_log('main')

    logtoconsolefallback(log)

    if options.ping_check is False:
        if options.access_token is None:
            raise SystemExit("Please specify the --access_token to use.")

        stats = Analytics.init(dict(
            url=options.url,
            defer=False,
            access_token=options.access_token
        ))

    else:
        stats = Analytics.init(dict(
            url=options.url, defer=False, access_token="no-needed"
        ))

    if options.ping_check is True:
        log.debug("uid: '{}'".format(options.uid))
        try:
            resp = stats.ping()

        except Exception:
            log.exception("failed to ping check the server!")
            sys.exit(1)

        else:
            log.info("ping check OK: {}".format(resp))

    else:
        if options.entry_id is not None:
            log.debug("Attempting to recover event id '{}' data".format(
                options.entry_id
            ))
            result = stats.get(options.entry_id)
            log.info("{}".format(result))

        else:
            log.debug("uid: '{}'".format(options.uid))

            log.debug("json loads of: '{}'".format(options.data))
            data = json.loads(options.data)

            if 'uid' not in data:
                data['uid'] = options.uid

            if 'event' not in data:
                data['event'] = options.event

            log.debug("event: '{}'".format(options.event))
            result = stats.log(data=data)
            log.info("event_id {}".format(result))

    sys.exit(0)
