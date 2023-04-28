# -*- encoding: utf-8 -*-
import multiprocessing
import os
import sys
from setuptools import setup, find_packages
from codecs import open
from setuptools.command.test import test as TestCommand

package_name = "claasp"


def read_file(file_name):
    with open(file_name, encoding='utf-8') as f:
        return f.read()


def run_tests(include_long_tests):
    number_of_cpus = multiprocessing.cpu_count()
    seconds_in_an_hour = 3600
    timeout_in_sec = seconds_in_an_hour * 7

    SAGE_BIN = ""
    if os.path.exists("SAGE_BIN_PATH"):
        SAGE_BIN = read_file("SAGE_BIN_PATH").strip()

    if len(SAGE_BIN) == 0:
        SAGE_BIN = "sage"

    long_test_flag = ""
    if include_long_tests:
        long_test_flag = "--long"

    errno = os.system(
        f"{SAGE_BIN} -t {long_test_flag} -T {timeout_in_sec} --nthreads {number_of_cpus} --force-lib " +
        package_name)
    if errno != 0:
        sys.exit(1)


class SageTestFast(TestCommand):
    def run_tests(self):
        run_tests(include_long_tests=False)


class SageTestAll(TestCommand):
    def run_tests(self):
        run_tests(include_long_tests=True)


setup(
    name=package_name,
    packages=find_packages(),
    version=read_file("VERSION").strip(),
    description='CLAASP: Cryptographic Library for Automated Analysis of Symmetric Primitives',
    long_description=read_file("README.md"),
    long_description_content_type="text/markdown",
    url='',
    author='TII Cryptanalysis Team',
    author_email='emanuele.bellini@tii.ae',
    license='GNU General Public License v3.0',
    package_data={
        '': [
            'cipher_modules/generic_bit_based_c_functions.c',
            'cipher_modules/generic_bit_based_c_functions.h',
            'cipher_modules/generic_word_based_c_functions.c',
            'cipher_modules/generic_word_based_c_functions.h'
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Science/Research',
        'Topic :: Software Development :: Build Tools',
        'Topic :: Scientific/Engineering :: Mathematics',
        'Programming Language :: Python :: 3',
    ],  # classifiers list: https://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords="",
    cmdclass={'testfast': SageTestFast, 'testall': SageTestAll},
    setup_requires=['sage-package', 'sphinx', 'bitstring'],
    install_requires=['sage-package', 'sphinx', 'bitstring']
)
