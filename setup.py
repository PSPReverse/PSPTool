#!/usr/bin/env python3

from setuptools import setup

setup(
    name='psptool2',
    version='1.0',
    description='psptool2 is a Swiss Army knife for dealing with AMD binary blobs for the Platform Security Processor '
                '(PSP) inside BIOS ROM files.',
    author='Christian Werling',
    author_email='cwerling@posteo.de',
    packages=['psptool2'],
    scripts=['bin/psptool', 'bin/psptool2', 'bin/psptrace'],
    install_requires=['prettytable'],
)
