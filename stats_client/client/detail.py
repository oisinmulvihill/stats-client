# -*- coding: utf-8 -*-
"""
Tools to glean more useful information out of a User Agents (Browser,
Mobile, etc).

Oisin Mulvihill
2016-04-22

"""
#import pycountry
from user_agents import parse


def ua_string_dict(ua_string):
    """Recover useful fields from the user agent string.

    This uses https://pypi.python.org/pypi/user-agents to achieve this.

    """
    user_agent = parse(ua_string)

    ua = dict(
        is_mobile=user_agent.is_mobile,
        is_tablet=user_agent.is_tablet,
        is_touch_capable=user_agent.is_touch_capable,
        is_pc=user_agent.is_pc,
        is_bot=user_agent.is_bot,
        browser_family=user_agent.browser.family,
        browser_version=user_agent.browser.version_string,
        os_family=user_agent.os.family,
        os_version=user_agent.os.version_string,
        device_family=user_agent.device.family,
    )

    return ua


# fields to extract from the request if possible:
AGENT_FIELDS = [
    'HTTP_USER_AGENT',
    'REQUEST_METHOD',
    'PATH_INFO',
    'HTTP_X_REAL_IP',
    'HTTP_ACCEPT_LANGUAGE',
    'REMOTE_ADDR',
    'HTTP_X_FORWARDED_FOR',
]


def agent(request):
    """Returns a dict of details about the remove UA from the request.

    The request object will have a META field (django) or and environ
    (pyramid)

    :returns: a dict.

    The dict returned will have lower cased fields found in the AGENT_FIELDS
    list.

    If the "http_user_agent" is present ua_string_dict() will be called to
    parse this. It will then place the results in a field called ua

    """
    agent_dict = {}

    if hasattr(request, 'META'):
        data_from = request.META

    else:
        data_from = request.environ

    for field in AGENT_FIELDS:
        agent_dict[field.lower()] = data_from.get(field, '')

    if "http_user_agent" in agent_dict:
        agent_dict['ua'] = ua_string_dict(
            agent_dict["http_user_agent"]
        )

    return agent_dict
