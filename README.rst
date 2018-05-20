SCEPy
=====

**SCEPy** is a pure python (sorta) implementation of a SCEP CA.

It is not intended for production use.

Getting Started
---------------

**SCEPy** is a Flask based web application which you can run like so::

    $ export FLASK_APP=scepy
    $ export SCEPY_SETTINGS=../scepy.cfg
    $ flask run

macOS
-----

You can visit ``/mobileconfig`` to download a SCEP profile which will enroll you with the service.

Debugging
---------

Console Log Predicates that are useful:

On iOS:

- Process: profiled
- Subsystem: com.apple.ManagedConfiguration
- Category: MC
