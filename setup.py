#!/usr/bin/env python
"""The setup script."""

try:
  from setuptools import find_packages, setup
except ImportError:
  from distutils.core import find_packages, setup

setup(name='hyperscan-python',
      version='0.1',
      description='Simple Python bindings for the Hyperscan project.',
      author='Andreas Moser',
      author_email='grrrrrrrrr@surfsup.at',
      license='Apache License, Version 2.0',
      packages=find_packages('.', exclude=[
          'tests'
      ]))
