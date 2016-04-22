# -*- coding: utf-8 -*-
"""
"""
import os
import uuid
import logging

import pytest


def get_log(e=None):
    return logging.getLogger("{0}.{1}".format(__name__, e) if e else __name__)


@pytest.fixture(scope='session')
def logger(request):
    """Set up a root logger showing all entries in the console.
    """
    log = logging.getLogger()
    hdlr = logging.StreamHandler()
    fmt = '%(asctime)s %(name)s %(levelname)s %(message)s'
    formatter = logging.Formatter(fmt)
    hdlr.setFormatter(formatter)
    log.addHandler(hdlr)
    log.setLevel(logging.DEBUG)
    log.propagate = False

    return log
