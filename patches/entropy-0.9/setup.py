#!/usr/bin/env python
from setuptools import setup, Extension


entropymodule = Extension(
    'entropy',
    sources=['entropymodule.c'],
    libraries=['m'],
)

setup(
    name='entropy',
    version='0.9',
    author='Martin Natano',
    author_email='natano@natano.net',
    description='extension module for calculating entropy fast',
    url='http://github.com/natano/python-entropy/',
    license='ISC',
    ext_modules=[entropymodule],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Utilities',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Development Status :: 3 - Alpha',
    ],
)
