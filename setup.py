#!/usr/bin/env python3

import sys
try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup

if not sys.version_info[0] == 3:
    sys.exit("Python 2.x is not supported; Python 3.x is required.")

########################################

setup(name="gp-saml-gui",
      version='0.1',
      description=" Interactively authenticate to GlobalProtect VPNs that require SAML",
      long_description=open("README.md").read(),
      author="Daniel Lenski",
      author_email="dlenski@gmail.com",
      license='GPL v3 or later',
      install_requires=list(open("requirements.txt")),
      url="https://github.com/dlenski/gp-saml-gui",
      py_modules = ['gp_saml_gui'],
      entry_points={ 'console_scripts': [ 'gp-saml-gui=gp_saml_gui:main' ] },
      )
