# This Makefile is for convenience as a reminder and shortcut for the most used commands

# Package folder
PACKAGE=claasp

# change to your sage command if needed
SAGE_BIN=`if [ -s SAGE_BIN_PATH ]; then cat SAGE_BIN_PATH; else echo sage; fi`
MODULE?=$(PACKAGE)

DOCKER_IMG_NAME=claasp
CURRENT_BRANCH=`git rev-parse --abbrev-ref HEAD`

all: install
	if [ $(CURRENT_BRANCH) == "master" ]; then\
		$(SAGE_BIN) setup.py testall;\
	else\
		$(SAGE_BIN) -t `{ git diff --name-only "*.py" ; git diff --name-only --staged "*.py"; } | uniq`;\
	fi

builddocker:
	docker build -f docker/Dockerfile -t $(DOCKER_IMG_NAME) .

rundocker: builddocker
	docker run -i -p 8888:8888 --mount type=bind,source=`pwd`,target=/home/sage/tii-claasp -t $(DOCKER_IMG_NAME) \
	sh -c "cd /home/sage/tii-claasp && make install && cd /home/sage/tii-claasp && exec /bin/bash"

builddocker-m1:
	docker build --build-arg="GUROBI_ARCH=armlinux64" -f docker/Dockerfile --platform linux/aarch64 -t $(DOCKER_IMG_NAME) .

rundocker-m1: builddocker-m1
	docker run -i -p 8888:8888 --mount type=bind,source=`pwd`,target=/home/sage/tii-claasp -t $(DOCKER_IMG_NAME) \
	sh -c "cd /home/sage/tii-claasp && make install && cd /home/sage/tii-claasp && exec /bin/bash"

install:
	$(SAGE_BIN) -pip install --upgrade --no-index -v .

uninstall:
	cd $(HOME) && $(SAGE_BIN) -pip uninstall $(PACKAGE) -y

develop:
	$(SAGE_BIN) -pip install --upgrade -e .

remote-pytest:
	pytest -v -n=auto --dist loadfile --cov-report xml:coverage.xml --cov=$(PACKAGE) tests/unit/

pytest:
	pytest -v -n=auto --dist loadfile tests/unit/

pytest-coverage:
	pytest -v -n=2 --dist loadfile --cov-report term-missing --cov=$(PACKAGE) tests/unit/

benchmark-tests:
	pytest -v tests/benchmark/

testfast:
	$(SAGE_BIN) setup.py testfast

testall: install
	$(SAGE_BIN) setup.py testall

test: install
	$(SAGE_BIN) -t $(MODULE)

coverage:
	$(SAGE_BIN) -coverage $(PACKAGE)/*

doc: install
	cd docs && python3 create_rst_structure.py html && $(SAGE_BIN) -sh -c "make html"

doc-pdf: install
	cd docs && python3 create_rst_structure.py pdf && $(SAGE_BIN) -sh -c "make latexpdf"

clean: clean-doc
	rm -rf build/
	rm -rf claasp.egg-info
	rm -rf claasp/sage/
	find . -type f -name '*.so' -delete
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

clean-doc:
	cd docs && $(SAGE_BIN) -sh -c "make clean"

distclean: clean
	rm -rf local/
	rm -rf upstream/

.PHONY: all install develop test coverage clean clean-doc doc doc-pdf

copyright: install
	python3 create_copyright.py

local-installation:
	./configure.sh

local-installation-m1:
	./configure.sh armlinux64
