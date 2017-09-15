#!/usr/bin/env python3

from datetime import datetime
from os import chdir
from os import pardir
from os import path
from setuptools import find_packages
from setuptools import setup
from subprocess import check_output

with open(path.join(path.dirname(__file__), '../README.md')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
chdir(path.normpath(path.join(path.abspath(__file__), pardir)))

git_version = check_output(['git', 'rev-list', '--count', 'HEAD']).decode('utf-8').strip(' +\r\n')
package_version = '0.{0}.{1}'.format(git_version, datetime.utcnow().strftime('%H%M'))

setup(
    name='django-talos',
    version=package_version,
    packages=find_packages(),
    include_package_data=True,
    license='BSD License',
    description='Alternative authentication, authorization and accounting application.',
    long_description=README,
    url='https://www.triflesoft.net/',
    author='Roman',
    author_email='adontz@gmail.com',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.10',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
