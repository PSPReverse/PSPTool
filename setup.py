#!/usr/bin/env python3

from setuptools import setup

setup(
    name='psptool',
    version='2.0',
    description='psptool is a Swiss Army knife for dealing with AMD binary blobs for the Platform Security Processor '
                '(PSP) inside BIOS ROM files',
    author='Christian Werling',
    author_email='crwerling@gmail.com',
    packages=['psptool'],
    scripts=['bin/psptool'],
    install_requires=['prettytable'],
)
