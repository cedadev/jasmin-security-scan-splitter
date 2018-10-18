#!/usr/bin/env python3

import os
from setuptools import setup, find_packages


here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md')) as f:
    README = f.read()

if __name__ == "__main__":
    setup(
        name = 'jasmin-security-scan-splitter',
        setup_requires = ['setuptools_scm'],
        use_scm_version = True,
        description = 'Utility for splitting up the JASMIN Unmanaged Cloud '
                      'security scan into per-project reports.',
        long_description = README,
        author = 'Matt Pryor',
        author_email = 'matt.pryor@stfc.ac.uk',
        url = 'https://github.com/cedadev/jasmin-security-scan-splitter',
        py_modules = ['security_scan_splitter'],
        include_package_data = True,
        zip_safe = False,
        install_requires = [
            'pandas',
            'xlrd',
            'openstacksdk',
            'jinja2',
            'markdown',
            'weasyprint',
            'click'
        ],
        entry_points = {
            'console_scripts': [
                'jss-parse=security_scan_splitter:main',
            ]
        }
    )
