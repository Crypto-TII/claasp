# How to contribute
To contribute to this project, please, follow the following conventions.
- [Project structure](#project-structure)
- [GIT Conventions](#git-conventions)
  - [Branches](#branches)
  - [Pull Requests](#pull-requests)
- [Best practices for development](#best-practices-for-development)
  - [Linter/Formatter](#linterformatter)
  - [Imports](#imports)
  - [File arrangement](#file-arrangement)
  - [Comments and dead code in the code](#comments-and-dead-code-in-the-code)
  - [Nomenclature](#nomenclature)
  - [Single quotes VS double quotes](#single-quotes-vs-double-quotes)
  - [Single underscore VS double underscore](#single-underscore-vs-double-underscore)
  - [C code](#c-code)
- [Testing](#testing)
  - [Running tests](#running-tests)
  - [Deprecation warnings](#deprecation-warnings)
- [Code analysis with SonarCloud](#code-analysis-with-sonarcloud)
  - [Project overview](#project-overview)
  - [Coverage](#coverage)
  - [Security Review](#security-review)
  - [Duplications](#duplications)
  - [Issues](#issues)
  - [It should be noted that...](#it-should-be-noted-that)
- [Changelog versioning](#changelog-versioning)
  - [Versioning](#versioning)
  - [How it works](#how-it-works)
    - [Branching](#branching)
    - [Commits messages](#commits-messages)
    - [Example](#example)
  

# Project structure
This is the current project structure.

```bash
.
├── CHANGELOG.md
├── claasp
│  ├── cipher_modules
│  ├── cipher.py
│  ├── ciphers
│  ├── component.py
│  ├── components
│  ├── DTOs
│  ├── editor.py
│  ├── __init__.py
│  ├── input.py
│  ├── name_mappings.py
│  ├── round.py
│  ├── rounds.py
│  └── utils
├── claasp.egg-info
│  ├── dependency_links.txt
│  ├── PKG-INFO
│  ├── requires.txt
│  ├── SOURCES.txt
│  └── top_level.txt
├── configure.sh
├── conftest.py
├── CONTRIBUTING.md
├── create_bash_script.py
├── create_copyright.py
├── docker
│  ├── Dockerfile
│  ├── README.md
│  └── tag-build.png
├── docs
│  ├── build
│  ├── CIPHER.md
│  ├── conf.py
│  ├── create_rst_structure.py
│  ├── DEVELOPER_GUIDE.md
│  ├── images
│  ├── Makefile
│  ├── README.md
│  ├── references.rst
│  ├── theme
│  └── USER_GUIDE.md
├── LICENSE
├── Makefile
├── publish_documentation.py
├── README.md
├── required_dependencies
│  ├── assess.c
│  ├── utilities.c
│  └── utilities.h
├── run_update_changelog.sh
├── setup.cfg
├── setup.py
├── sonar-project.properties
├── structure.txt
├── tests
│  ├── cipher_modules
│  ├── ciphers
│  ├── cipher_test.py
│  ├── components
│  ├── editor_test.py
│  └── utils
├── update_changelog.py
├── venv
│  ├── bin
│  ├── lib
│  └── pyvenv.cfg
└── VERSION
```


# GIT Conventions
## Branches
- `main` is the main branch.
- `develop` is the branch where the latest changes are merged into.
- `<fix-feature-breaking>/<task-name>` is the branch where a new feature is developed.

## Pull Requests
- Pull Requests should be made from a `feature-branch` to `develop` and it should be reviewed by at least one person.
- New branches to development tasks will have `develop` branch as origin. 
- The only allowed Pull Requests to `main` branch must come from `develop` branch. All other Pull Requests will be 
rejected.
- When a `develop` Pull Request to `main` is merged, a script will be executed to update the project version. See 
[Changelog versioning](#changelog-versioning) section.

# Best practices for development
The purposes of implementing these in our daily basis are:
- Keep a homogeneous code style throughout the project.
- Follow most of `PEP8` standard rules.
- Make code easier to read and understand.
- Reduce tendency to errors.
- Improve performance.

## Linter/Formatter
A best practice while developing is having a `linting` and a `formating` tool to help you follow the standard 
guidelines.
- **Linter**: reviews the code and documentation syntax based on the standard `Pep8`. We will use 
[pycodestyle](https://github.com/PyCQA/pycodestyle) + [pydocstyle](https://github.com/PyCQA/pydocstyle).
- **Formatter**: automatically formats Python code. We will use [autopep8](https://github.com/hhatto/autopep8), which 
uses the [pycodestyle](https://pypi.org/project/pycodestyle/) utility to determine what parts of the code needs to be 
formatted to conform to the `PEP8` style guide.

## Imports
- `PEP8` states a best practice to separate the end of the imports with the class or module definition by two blank 
lines. This **improves readability** and clearer knowledge of where the imports start and where they end.
```python
import numpy as np


class Calculator:
```

- We should **avoid to declare imports as**:
```python
from numpy import *
```
These type of imports bring everything that that module/file contains, even its own imports. This makes the cost of 
executing the code higher as it needs to resolve every import. Imagine that the module you are importing is importing 
other modules itself with this nomenclature, this can lead to cyclical imports or, in the worst case scenario, to 
import your hole project in the file without you even knowing. We should only import what we strictly need.

- When we need certain imports to make our string code to work, instead to adding them to the global imports, try to 
**import them where it is required only**. This will help us when we try to understand the code where those imports are 
really used. If we specify them globally, but they are only used in string code, probably our IDE will point to us that 
those imports are not used when they actually are.
```python
cipher_code_string = ""
cipher_code_string += "from copy import copy\n"
cipher_code_string += "from bitstring import BitArray\n"
cipher_code_string += "\n"
cipher_code_string += "def copy_array(input):\n"
```
This way of adding imports should also follow the recommendations described in this section.

- If we need to add a line of imports that is very long, specify those imports between parenthesis, this will help the 
formatter to split the import into multiple lines.
```python
from graph_representations.name_mappings import (INTERMEDIATE_OUTPUT,\
 CIPHER_OUTPUT, CONSTANT, WORD_OPERATION, MIX_COLUMN, SBOX)
```

## File arrangement
- `PEP8` states a best practice to leave a **blank line at the end of the file**.
- **Avoid writing infinite lines**. `PEP8` aims to have lines of less than 79 characters, we know that because of 
the nature of the project this would be nearly impossible to achieve, but we consider that writing lines of no more than 
120 characters can be achievable. This would mean a major improvement in readability.

## Comments and dead code in the code
- It is **not recommended to write comments in the code** unless they explain something specific that the code can't 
explain.
- It is a **bad practise having commented code**. When a piece of code is not needed, it needs to be removed. 
In case the programmer wants to recover it, he/she can do it from the version system control (Git).

## Nomenclature
- Variables, file names and methods should follow the same nomenclature as specified by `PEP8` 
[Naming Conventions](https://peps.python.org/pep-0008/#naming-conventions). This means to write them in snake_case 
avoiding usage of uppercase letters. In this project we have agreed to use uppercase notation for components naming. 
- On the other hand, for class naming we should use CamelCase avoiding the usage of underscore to separate the words.

## Single quotes VS double quotes
Below you can find what it is considered best practises, but the most important thing in this case, it is making an 
agreement among the team in order to use them in the same way, whether following best practises or not. 
- **Single quotes**: it's a best practice to use them to surround small and short strings, such as string literals or 
identifiers. But it's not a requirement. You can write entire paragraphs and articles inside single quotes. Example:
```python
name = 'Bob'
print(name)

channel = 'Better Data Science'
print(channel)

paragraph = 'Bob likes the content on Better Data Science. Bob is cool. Be like Bob.'
print(paragraph)
```
- **Double quotes**: It's considered a best practice to use them for natural language messages, string interpolations, 
and whenever you know there will be single quotes within the string. Example:
```python
name = 'Bob'

# Natural language
print("It is easy to get confused with single and double quotes in Python.")

# String interpolation
print(f"{name} said there will be food.")

# No need to escape a character
print("We're going skiing this winter.")

# Quotation inside a string
print("My favorite quote from Die Hard is 'Welcome to the party, pal'")
```

## Single underscore VS double underscore
- The use of single underscore is **related to protected variables and methods**, this means that no other object or 
method is able to reach them unless they are part of a child object (Inheritance).
- Double underscores are used to state that **methods are private** and no other objets can use them even if they are
children.
- In this project we have agreed to only use Single underscore notation for both purposes. 

## C-code
`PEP8` has a specific guideline on how to deal with  C code in the 
[C implementation of Python](https://peps.python.org/pep-0007/).

# Testing
The project uses **`Pytest` as it’s testing framework**. We can forget to write the example Docstrings as they will 
still be part of the documentation.
Our tests are stored in the `tests` folder that mimics the folder structure of `claasp`.

There are files in our `claasp` folder that are not in the `test` folder, this means that those files does not contain 
any tests. So every time we create a new file that should have tests in `claasp` we would need to create a new test 
file. Test files are named exactly the same as our `claasp` files, we just need to add `_test` at the end of the name. 

As an example `cipher.py` needs a test file called `cipher_test.py`.

Once we have created our test file, we need to create the test. The test file works as common Python files. So we need 
to declare our testing functions and our imports. Our function names follow the structure of 
`test_{name of the method we want to test}`.

- **Docstring**:
```bash
sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
sage: aes = AESBlockCipher()
sage: key = 0x2b7e151628aed2a6abf7158809cf4f3c
sage: plaintext = 0x6bc1bee22e409f96e93d7e117393172a
sage: ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
sage: aes.evaluate([key, plaintext]) == ciphertext
True
```

- **Pytest**:
```python
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher


def test_aes_block_cipher():
    aes = AESBlockCipher()
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x6bc1bee22e409f96e93d7e117393172a
    ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
    assert aes.evaluate([key, plaintext]) == ciphertext
```

As you can see above, the `assert` keyword is the one that will check if our result is the one we expected. 
Apart from that, the structure of the test is very similar.

## Running tests
To run all the project test you can run `make pytest command`, but if you want to run specific things you can do:
- **Run specific file:**
```bash
pytest -v tests/cipher_test.py
```
- **Run specific test in file:**
```bash
pytest -v tests/cipher_test.py::test_algebraic_tests
```
- **Run the tests to show full log of error:**
```bash
pytest -vv tests/cipher_test.py
```
- **Run the tests to show prints and standard outputs:**
```bash
pytest -s tests/cipher_test.py
```

If we want a **specific test to be skipped** we will need to `import pytest` to the top of the file and add this 
following command with the reason of the test being skipped as the argument `@pytest.mark.skip("Takes to long")`:
```python
import pytest

from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher

@pytest.mark.skip("Takes to long")
def test_aes_block_cipher():
    aes = AESBlockCipher()
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x6bc1bee22e409f96e93d7e117393172a
    ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
    assert aes.evaluate([key, plaintext]) == ciphertext
```

## Deprecation warnings
We might get sometime deprecation warnings. To avoid them we can import `pytest` to the top of the file and add this 
following command `@pytest.mark.filterwarnings("ignore::DeprecationWarning:")`:
```python
import pytest

from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher

@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_aes_block_cipher():
    aes = AESBlockCipher()
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x6bc1bee22e409f96e93d7e117393172a
    ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
    assert aes.evaluate([key, plaintext]) == ciphertext
```

# Code analysis with SonarCloud
SonarCloud is a platform to evaluate the quality of the source code of a project detecting errors, vulnerabilities and 
bugs in software.

## Project overview
SonarCloud is responsible for the analysis of our code once a pull request has been created.

We have two tabs in the general view:
- **New Code**: we find a detailed report on the code quality of the last push, taking into account only the new code 
and/or the modified code.
- **Overall Code**: shows the overall report of the project status.

## Coverage
The coverage of the project is the **percentage of lines of code that are covered by the tests**.
Clicking on the percentage or the number of lines takes us to the list of files.

## Security Review
A security hotspot is a piece of code that is sensitive to the security of the project and must be reviewed and fixed.

## Duplications
When we talk about duplications, we are referring to code already written in the project that is repeated several 
times. SonarCloud also tells us where these repetitions are occurring and will tell us the percentage of duplicated 
lines in our code.
Clicking on the percentage or the number of duplicate lines will take us to the list of files containing duplicate code.

## Issues
This section reflects the problems found in our code that we should fix. 

SonarCloud's report provides detailed information on each problem encountered as well as suggestions on how to solve it.

The problems are divided into 3 types:
- **Bugs**: problems that cause the code to behave incorrectly.
- **Vulnerabilities**: problems that can be exploited by attackers to compromise the confidentiality, integrity or 
  availability of the software.
- **Code Smells**: problems that affect the maintainability of the code.

The **severity** of the problems in our code are divided into 5 types:
- **Blocker**: the problem is critical and must be fixed immediately.
- **Critical**: the problem is critical and must be fixed as soon as possible.
- **Major**: the problem is important and should be fixed.
- **Minor**: the problem is not very important and should be fixed if possible.
- **Info**: the problem is not important and does not need to be fixed.

When the problem has been solved by updating our code, a new push re-runs the analysis process.
Similarly, when reviewing a problem detected in the SonarCloud report, if we consider that it is not a problem, we can 
mark it as "Resolved as won't fix".

## It should be noted that...
If in the new push there is more than **3% duplicate code** and/or the **test coverage is less than 80%** the pipeline 
analysis will fail, as well as, if there are new Security Hotspots and/or bugs in the code during a new push.

# Changelog versioning
To automate the project version increment, the script `update_changelog.py` has been created to be executed when a Pull 
Request is merged from the `develop` branch to the `main` branch.
This script analyzes the name of the branches to determine the type of version increment and the commit messages to 
determine the information that should be added to the `CHANGELOG.md`.

> ⚠️ It is important to follow the following rules only in case we want to upgrade the project version at the end of the 
> task. Otherwise, do not follow the following rules as it will cause an unwanted change in the project version. ⚠️ 


## Versioning
There are three types of versioning changes, as you can check in [Semantic Versioning](https://semver.org/):

- [x.x.<font color="purple">**x**</font>] - **Patch** &rarr; When you make compatible bug fixes.
- [x.<font color="purple">**x**</font>.x] - **Minor** &rarr; When you add functionality in a compatible manner.
- [<font color="purple">**x**</font>.x.x] - **Major** &rarr; When you make incompatible changes.

## How it works

### Branching
The name of the branches must be created according to this structure, because of that depends the type of change for 
the new version.

- For **patch** changes: <font color="purple">**fix</font>/name-of-task**
- For **minor** changes: <font color="purple">**feat</font>/name-of-task**
- For **major** changes: <font color="purple">**breaking</font>/name-of-task**

We will look in the commits merged into `develop` to obtain the highest version change to be applied.
**By default**, if we don’t find any branch with this structure, **the change to apply will be fix**.

### Commits messages
The information that will be included in the new version will be taken from the messages of the commits of all the Pull 
Requests that have been merged into `develop`. Then, we will check the commits between the last merge from `develop` 
to `main`. Those merge commits will have a message like this: **"Merge pull request #x from /develop"**.

The selected commit messages to be included in the description of the new version must start with these keywords 
followed by colon as showed below added to their corresponding section in the `CHANGELOG.md`:

- **Add: / Feat: / Feature: → <font color="purple">Added</font>**
- **Change: / Refactor: → <font color="purple">Changed</font>**
- **Fix: → <font color="purple">Fixed</font>**
- **Remove: → <font color="purple">Removed</font>**

The commits that do not start by those keywords will be ignored and not added to the version information in the 
`CHANGELOG.md`. 

Also, **if there is no commit that start with those keywords, the version will not be upgraded**.

### Example
Let's see an example of how the versioning works:

- The last version in `CHANGELOG.md` is `4.0.1`.
- The branch name is `feat/LIBCA-36-login-creation`.
- We have this list of valid commits messages:
  - **Add: create new component**
  - **Feat: create login form**
  - **Change: update Version variables from destructuring list**
  - **Fix: update coverage path**
  - **Remove: remove comented code**
  - **Refactor: code refactorings in cipher.py**

We will have a new version 4.2.0 with the following information in the `CHANGELOG.md`:

```markdown
## [4.2.0] - 2023-04-27

### Added

- Create new component.
- Create login form.

### Changed

- Update Version variables from destructuring list.
- Code refactorings in cipher.py.

### Fixed

- Update coverage path.

### Removed

- Remove comented code.
```
