# -*- coding: utf-8 -*-
"""
No tests here, all testing is done in the stats-service. I have this token test
to satisfy my own build / release system.

Oisin Mulvihill
2016-04-22

"""


def test_some_functionality(logger):
    logger.warn("Testing of the client is done when testing the stats service")
    assert 1 == 1
