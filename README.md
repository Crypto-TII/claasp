# CLAASP: A Cryptographic Library for the Automated Analysis of Symmetric Primitives

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Crypto-TII_claasp&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Crypto-TII_claasp)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Crypto-TII_claasp&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=Crypto-TII_claasp)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=Crypto-TII_claasp&metric=bugs)](https://sonarcloud.io/summary/new_code?id=Crypto-TII_claasp)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=Crypto-TII_claasp&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=Crypto-TII_claasp)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Crypto-TII_claasp&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=Crypto-TII_claasp)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=Crypto-TII_claasp&metric=coverage)](https://sonarcloud.io/summary/new_code?id=Crypto-TII_claasp)

This package is designed as a software tool to automate as much as possible the analysis of the design of symmetric primitives 
such as block ciphers, cryptographic permutations, hash functions, and stream ciphers, from a cryptanalytic point of view.
It is built on the top of [SageMath](http://www.sagemath.org) and
implemented using [Python3](https://www.python.org/).

## Documentation

### User's Guide

A brief user's guide with instructions on how to get started with CLAASP 
is available in `docs/USER_GUIDE.md` file.

### Developer's Guide

A brief developer's guide with instructions on how to contribute to the project 
is available in `docs/DEVELOPER_GUIDE.md` file.
 
### Full documentation

Detailed documentation containing description of each module, with examples, can be found 
in https://claasp.readthedocs.io/en/latest/.

You can generate the documentation locally by following the instructions in `docs/USER_GUIDE.md` file. 
These instructions allow to generate:

- an HTML interactive documentation available in `docs/build/html/index.html` that can be opened in any browser.
 
- a PDF documentation available in `docs/build/latex/claasp.pdf`.

## Source code

All source code is stored in the folder `claasp/`.

## Contributing
We want you to help us grow this library, so, please, feel free to submit your Pull Request following the 
[CONTRIBUTING.md](docs/CONTRIBUTING.md) conventions.
