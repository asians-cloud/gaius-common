#!/usr/bin/env python

import os
from setuptools import setup, find_packages

__version__ = "1.0.0"

here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, 'README.rst')) as f:
    long_description = f.read().strip()

setup(
    name='gaius-common',
    version=__version__,
    author='gaius',
    author_email='gaius@asians.cloud',
    url='http://github.com/rq0net/gaius-common',
    license='Apache License 2.0',
    description='Auth Public. Read the README.rst for more information.',
    packages=find_packages(),
    long_description=long_description,
    long_description_content_type='text/x-rst',
    keywords='django rest auth registration rest-framework django-registration api docker cookiecuter tox pytest',
    zip_safe=False,
    include_package_data=True,
    python_requires=">=3.8",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Framework :: Django :: 2.2',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Internet :: WWW/HTTP'
    ],
)