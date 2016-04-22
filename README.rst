stats-client
============

.. contents::


Introduction
------------

The stats-service basic REST client library. This sets up token auth and allows
the build of in-house customer analytics gathering. These custom metrics are
then send to the stats-service. It stores them in InfluxDB and Grafana is used
to write in-house rules for graphing.

Development
-----------

Activate the dev environment and change into stats-client and do::

    python setup.py develop


Testing
-------

From here you can do::

    python setup.py test

