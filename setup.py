#!/usr/bin/env python3

import sys
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

########################################

setup(
    name="gp-saml-gui",
    version='0.1',
    description="Interactively authenticate to GlobalProtect VPNs that require SAML",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type='text/markdown',
    author="Daniel Lenski",
    author_email="dlenski@gmail.com",
    license='GPL v3 or later',
    python_requires=">=3.5",
    install_requires=list(open("requirements.txt")),
    url="https://github.com/dlenski/gp-saml-gui",
    py_modules = ['gp_saml_gui'],
    entry_points={ 'console_scripts': [ 'gp-saml-gui=gp_saml_gui:main' ] },
    data_files=[('share/man/man8', ['gp-saml-gui.8'])],
)
