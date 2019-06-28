==================================
Open Balkans Python Implementation
==================================


.. image:: https://img.shields.io/pypi/v/openbalkans.svg
        :target: https://pypi.python.org/pypi/openbalkans

.. image:: https://img.shields.io/travis/andecy64/openbalkans.svg
        :target: https://travis-ci.org/andecy64/openbalkans

.. image:: https://readthedocs.org/projects/openbalkans/badge/?version=latest
        :target: https://openbalkans.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status


A python implementation of OpenBalkans


* Free software: MIT license
* Documentation: https://openbalkans.readthedocs.io.

Features
--------

TODO
----

* Write a function that generates and saves the key to file
* Write a method that creates configuration file and allows different formats
* Format should be loaded from yaml or json


Plans
-----

* consider using config file - will create and use one
* think of key designation scheme
* user should be able to choose between WarpWallet and keyfile
* simple api (object.create_post(payload)) should be available and support lists
* only ECDSA should be supported with this implementation
* Key wrapper object and post interface should be extensible to allow different encryption types


Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage

