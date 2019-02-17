#!/usr/bin/env python3

from setuptools import setup

setup(
    name='psptool2',
    version='1.0',
    description='psptool2 is a Swiss Army knife for dealing with AMD binary blobs for the Platform Security Processor '
                '(PSP) inside BIOS ROM files.',
    author='Christian Werling',
    author_email='crwerling@gmail.com',
    packages=['psptool2'],
    scripts=['bin/psptool2'],
    install_requires=['prettytable'],
)
