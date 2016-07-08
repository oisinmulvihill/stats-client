# -*- coding: utf-8 -*-
"""
"""
import json
import socket
import logging
import threading
from urlparse import urljoin

import requests
from apiaccesstoken.clientside import RequestsAccessTokenAuth


def get_log(e=None):
    return logging.getLogger("{0}.{1}".format(__name__, e) if e else __name__)


# Set up by a call to Analytics.init(...):
__Analytics = None


class Analytics(object):
    """A light namespace for the REST API to stats-service.
    """

    JSON_CT = {
        # I accept JSON:
        'Accept': 'application/json',
        # I POST JSON:
        'Content-Type': 'application/json',
    }

    ANALYTICS = '/log/event/'

    EVENT = '/log/event/{}/'

    def __init__(self, config={}):
        """Set up the analytics REST API service details.

        :param config: a dict

        E.g.::

            config = {
                # Don't log events, noop them instead.
                "disabled": True,

                "access_token": "<access token string>",

                # The analytics service to connect to:
                "url": "http://localhost:20080",

                # Log asynchronusly and don't wait for a response.
                "defer": True,

                # optional dict which become "tags" in logged events. If not
                # set "tags" field won't be present in logged events.
                "tags": A dict of key-value pairs to include in a event log.
            }

        tags example::

            {"mode": "prodution" | "development"}

        If defer is True return letting a thread handle the POST. The
        raise_for_status() will be logged and not raised.

        """
        log = get_log("Analytics.init")
        self.disabled = config.get("disabled", False)
        self.base_uri = config.get("url", "http://localhost:20080")
        self.tags = config.get("tags", {})
        log.debug(
            "Logging events to stats-service '{}'.".format(self.base_uri)
        )
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

    @classmethod
    def init(cls, config={}):
        """Set up the Analytics instance for stats() to return.

        :param config: The URI of the analytics service.

        If no 'uri' field is set or is empty the analytics logging will be
        disabled after logging a single warning. This allows analytics to be
        turned off with causing errors.

        """
        global __Analytics
        __Analytics = Analytics(
            dict(
                # Disable event logging if the uri is empty:
                disabled=config.get("disabled"),
                access_token=config.get("access_token"),
                url=config.get("url"),
                defer=config.get("defer", True),
            )
        )
        return __Analytics

    @classmethod
    def stats(cls):
        """Return the configured Analytics instance set up by init()."""
        assert __Analytics is not None
        return __Analytics

    def get_auth(self):
        """Recover the configured access auth instance."""
        if not self.auth:
            raise ValueError(
                "No access token set! Please call set_auth() or login()."
            )
        return self.auth

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
        tags = dict(
            uid="system-{}".format(self.app_node),
            ip=socket.gethostbyname(self.app_node),
            hostname=self.app_node,
        )
        # add in extra tags if they have been specified
        for key in self.tags:
            tags[key] = unicode(self.tags[key])

        points = [dict(
            measurement='server_startup',
            tags=tags,
            fields=dict(
                # will allow you to count() the number of startups.
                # lots/<time period e.g. min,day,etc> is probably bad :)
                value=1
            )
        )]
        self.log(points)

    def log(self, points):
        """Log an analytics event string with the given data.

        :param points: InfluxDB points.

        """
        log = get_log("Analytics.log")

        if self.disabled is True:
            if self._log_is_disabled is False:
                log.warn("Analytics is disabled in configuration!")
                self._logdisabled = True
            return

        uri = urljoin(self.base_uri, self.ANALYTICS)
        points = json.dumps(points)

        def _go(defer, uri, data):
            #log.debug("sending data '{}' to '{}'".format(data, uri))
            returned = ""
            try:
                resp = requests.post(
                    uri,
                    data=data,
                    headers=self.JSON_CT,
                    auth=self.get_auth()
                )

            except requests.exceptions.ConnectionError, e:
                log.warn("Uable to connect to log event: {}".format(e))

            else:
                if resp.status_code > 399:
                    log.error("Log event error: {} {}".format(
                        resp.status_code, resp
                    ))

                else:
                    returned = resp.json()

            return returned

        if self.defer:
            t = threading.Thread(target=_go, args=(self.defer, uri, points))
            t.daemon = True
            t.start()

        else:
            return _go(self.defer, uri, points)
