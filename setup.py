#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

from openbalkans import __version__ as version

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
        "cryptography==2.8",
        "w3lib==1.21.0",
    ]

setup_requirements = []

test_requirements = [
    "tox",
    ]

setup(
    author="Barak Avrahami",
    author_email='barak1345@gmail.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    description="A python implementation of OpenBalkans",
    install_requires=requirements,
    license="MIT license",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='openbalkans',
    name='openbalkans',
    packages=find_packages(include=['openbalkans']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    python_requires=">=3",
    url='https://github.com/openbalkans/openbalkans-python',
    version=version,
    zip_safe=False,
)
