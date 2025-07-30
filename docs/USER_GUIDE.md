# User's Guide for CLAASP Library

In this guide we provide instruction for a user to start using CLAASP: Cryptographic Library for Automated Analysis of Symmetric Primitives library.

This package is designed as a cryptanalysis tool to examine properties of Boolean functions, S-Boxes, block ciphers, stream ciphers, public-key, digital signatures, etc. It is built on the top of [SageMath](http://www.sagemath.org) and implemented using [Python3](https://www.python.org/) and [Cython](https://www.cython.org).

## Installation

Download the source from the git repository:

```
    $ git clone https://github.com/Crypto-TII/claasp.git
    $ cd claasp/
```

CLAASP library is built on the top of SageMath, and it will try to pick the `sage` binary from `PATH` environment variable. Alternatively, you can specify different sage binary in the file `SAGE_BIN_PATH` if you want to use other version of SageMath.

There are two different ways of getting the library ready to use, using pip, docker or installing the dependencies on your machine. If you choose to use Docker, the dependencies will not be installed. These will remain inside your docker image and will be deleted as soon as you delete that image.

### Using pip

You can install CLAASP using `pip` with the commands:

```bash
    $ python3 -m venv your_venv_name
    $ source your_venv_name/bin/activate
    $ pip install claasp
```

In order to use the library, you have to manually install other dependencies:
- `dieharder` version `3.31.1.2-1build1`;
- `latexmk` version `1:4.76-1`;
- `python3-cryptominisat` version `5.8.0+dfsg1-2`;
- `sagemath` version `9.5-4`.

### Docker

In order to use this approach you need to have [Docker](https://www.docker.com/) installed and up in your machine.

After you have installed and opened it, you can run the command in the terminal that will create the image and launch the container.

#### Using Makefile

- In case you use a macOS machine with Apple Silicon chip (arm64), you need to run the command

    ```make rundocker-m1```

- Otherwise, run

    ```make rundocker```

After the installation, you need to enter to the sage terminal with the command:

```sage```

After that you are ready to go and can use the library as specified in the [usage](#usage) section.

#### Using docker-compose

You can alternatively use `docker-compose`.

1. **Create the service**  
    Run `docker compose create environment`.
2. **Start the container**  
    Run `docker start -ia claasp-container`.
3. **Have fun with library**  
    Enter the Sage terminal with `sage` command and follow [usage](#usage).
4. **Exit the container**  
    When you exit the container, you can restart whenever you want at point 2.
5. **Clean (optionally)**  
    If you want to regain some space, just run `docker rm claasp-container; docker rmi tiicrc/claasp:local`.

### Manual installation

To install the dependencies manually, you can do it through make command or executing a script from the root directory of the project. Before doing this, make sure that you have set up `locale` correctly.

#### Make command

You need to have `make` installed for this execution. Run ```make local-installation```.

#### Script execution

Alternatively, you can run ```./configure.sh```.

## Documentation

If you want to deep dive in the library, check how it works and what you can do with it, you can generate the documentation in two different formats: an HTML page or a pdf file. You can find both ways of generating it below.

### HTML

The HTML documentation of the package can be generated using Sage's ``Sphinx`` by calling:

    $ make clean-doc
    $ make doc

The documentation is available in `docs/build/html/index.html` and can be opened using any browser. 

### PDF

An alternative is to generate the PDF version by running:

    $ make clean-doc
    $ make doc-pdf
    
The resulting PDF is available in `docs/build/latex/claasp.pdf`.

## Copyright

Every new file created inside `claasp` folder must include de project copyright. You can generate it by running:

    $ make copyright

## Usage

Once the package is installed, you can use it in Sage with:

    sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
    sage: fancy = FancyBlockCipher(number_of_rounds=4)
    sage: key = 0xFFFFFF
    sage: plaintext = 0x000000
    sage: fancy.evaluate([plaintext, key])

## Contributing the library

To contribute to the library, please follow the instructions in `docs/CONTRIBUTING.md` file.
