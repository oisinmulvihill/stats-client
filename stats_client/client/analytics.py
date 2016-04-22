# -*- coding: utf-8 -*-
"""
"""
import json
import socket
import logging
import datetime
import threading
from urlparse import urljoin

import requests
from pp.apiaccesstoken.restclientside import RequestsAccessTokenAuth

from stats.client.dflatten import flatten


def get_log(e=None):
    return logging.getLogger("{0}.{1}".format(__name__, e) if e else __name__)


class Analytics(object):
    """A light namespace for the REST API to stats.service.
    """

    JSON_CT = {'Content-Type': 'application/json'}

    ANALYTICS = '/log/event/'

    def __init__(self, config={}):
        """Set up the analytics REST API service details.

        :param config: a dict

        E.g.::

            config = {
                # Don't log events, noop them instead.
                "disabled": True,

                "access_token": "<access token string>",

                # The analytics service to connect to:
                "uri": "http://localhost:20080",

                # Log asynchronusly and don't wait for a response.
                "defer": True,
            }

        If defer is True return letting a thread handle the POST. The
        raise_for_status() will be logged and not raised.

        """
        log = get_log("Analytics.init")
        self.disabled = config.get("disabled", False)
        self.base_uri = config.get("uri", "http://localhost:20080")
        self.defer = config.get("defer", True)
        self.app_node = socket.gethostname()
        # once-off log analytics is disable in a call to self.log()
        self._log_is_disabled = False
        access_token = config.get("access_token")
        if not access_token and not self.disabled:
            raise ValueError("access_token us not set!")
        else:
            log.debug("access token set.")
        self.auth = RequestsAccessTokenAuth(access_token)
        log.debug("REST Service base URI: {}".format(self.base_uri))

    def get_auth(self):
        """Recover the configured access auth instance."""
        if not self.auth:
            raise ValueError(
                "No access token set! Please call set_auth() or login()."
            )
        return self.auth

    def now(self):
        """Returns the current UTC date and time."""
        return datetime.datetime.utcnow()

    def ping(self):
        """Recover the API Service status page.

        This will raise a connection error or it will return successfully.

        :returns: service status dict.

        """
        log = get_log('ping')

        uri = urljoin(self.base_uri, 'ping/')
        log.debug("contacting '{}'".format(uri))

        resp = requests.get(uri, headers=self.JSON_CT)

        resp.raise_for_status()

        return resp.json()

    def system_startup(self):
        """Log the start of a service on a machine.
        """
        log = get_log("Analytics.system_startup")

        data = dict(
            event='pnc.server.start',
            uid="system-{}".format(self.app_node),
            ip=socket.gethostbyname(self.app_node),
            app_node=self.app_node,
        )

        log.debug("data:{}".format(data))
        self.log(data)

    def log(self, data={}):
        """Log an analytics event string with the given data.

        :param data: A dict which can be converted to JSON and sent.

        At a minimum it will need to contain the uid and event fields.

            uid: A unique id used to tie together analytic events.

            event: A string naming the event e.g. 'pnc.user.login'

        """
        log = get_log("Analytics.log")

        if self.disabled is True:
            if self._log_is_disabled is False:
                log.warn("Analytics is disabled in configuration!")
                self._logdisabled = True
            return

        if 'datetime' not in data:
            data['datetime'] = self.now().isoformat()

        data = flatten(data)
        #print("AFTER FLATTEN data:{}".format(json.dumps(data, indent=4)))

        uri = urljoin(self.base_uri, self.ANALYTICS)

        assert 'uid' in data
        assert 'event' in data

        data = json.dumps(data)

        def _go(defer, uri, data):
            log.debug("sending data '{}' to '{}'".format(data, uri))
            resp = requests.post(
                uri,
                data=data,
                headers=self.JSON_CT,
                auth=self.get_auth()
            )
            try:
                resp.raise_for_status()

            except:
                log.exception(
                    "Error sending data '{}' to '{}': ".format(data, uri)
                )
                if not defer:
                    raise

            return resp.json()

        if self.defer:
            t = threading.Thread(target=_go, args=(self.defer, uri, data))
            t.daemon = True
            t.start()

        else:
            return _go(self.defer, uri, data)


__Analytics = None


def init(config={}):
    """Set up the Analytics instance for stats() to return.

    :param config: The URI of the analytics service.

    If no 'uri' field is set or is empty the analytics logging will be disabled
    after logging a single warning. This allows analytics to be turned off with
    causing errors.

    """
    global __Analytics
    __Analytics = Analytics(
        dict(
            # Disable event logging if the uri is empty:
            disabled=config.get("disabled"),
            access_token=config.get("access_token"),
            uri=config.get("uri"),
            defer=config.get("defer", True),
        )
    )


def stats():
    """Return the configured Analytics instance set up by init()."""
    assert __Analytics
    return __Analytics
