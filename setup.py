# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

import pathspider.base

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

with open('requirements.txt') as f:
    install_requires = f.read().splitlines()

setup(
    name='pathspider',
    version=pathspider.base.__version__,
    description='A tool for measuring path transparency in the Internet',
    long_description=long_description,
    url='https://pathspider.net/',
    author='Iain Learmonth',
    author_email='irl@fsfe.org',
    license='GNU GPLv2',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',

        # The UI
        'Environment :: Console',

        # Indicate who your project is intended for
        'Intended Audience :: Science/Research',
        'Topic :: Communications',
        'Topic :: Internet',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',

        # Specify the Python versions you support here
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    keywords='internet measurement ecn dns web www analysis router congestion path transparency latency diffserv dscp',

    packages=find_packages(exclude=['contrib', 'doc', 'examples']),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'pspdr=pathspider.cmd.base:handle_args_wrapper',
        ],
    },
    test_suite = 'nose.collector',
    test_requires = 'nose',
)
