# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

with open(path.join(here, 'pathspider', 'VERSION'), encoding='utf-8') as version_file:
    version = version_file.read().strip()

with open('requirements.txt') as f:
    install_requires = f.read().splitlines()

setup(
    name='pathspider',
    version=version,
    description='A tool for measuring path transparency in the Internet',
    long_description=long_description,
    url='https://pathspider.net/',
    author='Iain Learmonth',
    author_email='irl@fsfe.org',
    license='GNU GPLv2',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 5 - Production/Stable',

        # Indicate who your project is intended for
        'Intended Audience :: Science/Research',
        'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],

    keywords='internet measurement ecn tfo dns web www analysis router congestion path transparency latency diffserv dscp',

    packages=find_packages(exclude=['contrib', 'doc', 'tests*']),
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'pathspider=pathspider.run:handle_args_wrapper',
        ],
    },
)
