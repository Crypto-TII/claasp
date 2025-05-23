# This Makefile is for convenience as a reminder and shortcut for the most used commands

# Package folder
PACKAGE=claasp

# Change to your sage command if needed
SAGE_BIN=`if [ -s SAGE_BIN_PATH ]; then cat SAGE_BIN_PATH; else echo sage; fi`
MODULE?=$(PACKAGE)

DOCKER_IMG_NAME=claasp
CURRENT_BRANCH=`git rev-parse --abbrev-ref HEAD`


all: install
	if [ $(CURRENT_BRANCH) == "main" ]; then\
		$(SAGE_BIN) setup.py testall;\
	else\
		$(SAGE_BIN) -t `{ git diff --name-only "*.py" ; git diff --name-only --staged "*.py"; } | uniq`;\
	fi

builddocker:
	docker build -f docker/Dockerfile --target claasp-base -t $(DOCKER_IMG_NAME) .

rundocker:
	docker run -i -p 8887:8887 --cpus=6 --mount type=bind,source=`pwd`,target=/home/sage/tii-claasp -t $(DOCKER_IMG_NAME) \
	sh -c "cd /home/sage/tii-claasp && make install && cd /home/sage/tii-claasp && exec /bin/bash"

rundockerhub:
	docker pull tiicrc/claasp-base \
	docker run -i -p 8887:8887 --mount type=bind,source=`pwd`,target=/home/sage/tii-claasp -t $(DOCKER_IMG_NAME) \
	sh -c "cd /home/sage/tii-claasp && make install && cd /home/sage/tii-claasp && exec /bin/bash"

builddocker-m1:
	docker build -f docker/Dockerfile --platform linux/x86_64 --target claasp-base -t $(DOCKER_IMG_NAME) .

rundocker-m1: builddocker-m1
	docker run -i -p 8888:8888 --mount type=bind,source=`pwd`,target=/home/sage/tii-claasp -t $(DOCKER_IMG_NAME) \
	sh -c "cd /home/sage/tii-claasp && make install && cd /home/sage/tii-claasp && exec /bin/bash"

rundockerhub-m1:
	docker pull tiicrc/claasp-m1-base \
	docker run -i -p 8888:8888 --mount type=bind,source=`pwd`,target=/home/sage/tii-claasp -t $(DOCKER_IMG_NAME) \
	sh -c "cd /home/sage/tii-claasp && make install && cd /home/sage/tii-claasp && exec /bin/bash"

install:
	$(SAGE_BIN) -pip install --upgrade --no-index -v .

uninstall:
	cd $(HOME) && $(SAGE_BIN) -pip uninstall $(PACKAGE) -y

develop:
	$(SAGE_BIN) -pip install --upgrade -e .

remote-pytest:
	pytest -v -n=16 --dist loadfile \
  --cov-report xml:coverage.xml --cov=$(PACKAGE) \
  --randomly-seed=1553614239 \
  --ignore=tests/unit/cipher_modules/statistical_tests \
  --ignore=tests/unit/cipher_modules/models/cp \
  --ignore=tests/unit/cipher_modules/report_test.py \
  --ignore=tests/unit/ciphers/stream_ciphers/zuc_stream_cipher_test.py \
  --ignore=tests/unit/ciphers/stream_ciphers/trivium_stream_cipher_test.py \
  --ignore=tests/unit/ciphers/toys/toyspn1_test.py \
  --ignore=tests/unit/ciphers/toys/toyfeistel_test.py \
  --ignore=tests/unit/ciphers/toys/toy_cipherFOUR_test.py \
  --ignore=tests/unit/ciphers/toys/toyspn2_test.py \
  --ignore=tests/unit/ciphers/stream_ciphers/a5_1_stream_cipher_test.py \
  --ignore=tests/unit/ciphers/permutations/spongent_pi_precomputation_permutation_test.py \
  --ignore=tests/unit/ciphers/permutations/keccak_invertible_permutation_test.py \
  --ignore=tests/unit/ciphers/permutations/spongent_pi_fsr_permutation_test.py \
  --ignore=tests/unit/cipher_modules/neural_network_tests_test.py \
  --ignore=tests/unit/ciphers/stream_ciphers/a5_2_stream_cipher_test.py \
  --ignore=tests/unit/ciphers/permutations/spongent_pi_permutation_test.py \
  --ignore=tests/unit/ciphers/stream_ciphers/bluetooth_stream_cipher_e0_test.py \
  --ignore=tests/unit/ciphers/permutations/xoodoo_invertible_permutation_test.py \
  --ignore=tests/unit/ciphers/permutations/tinyjambu_32bits_word_permutation_test.py \
  --ignore=tests/unit/ciphers/permutations/tinyjambu_fsr_32bits_word_permutation_test.py \
  --ignore=tests/unit/cipher_modules/statistical_tests/dieharder_statistical_tests_test.py \
  --ignore=tests/unit/ciphers/permutations/keccak_sbox_permutation_test.py \
  --ignore=tests/unit/ciphers/permutations/xoodoo_permutation_test.py \
  --ignore=tests/unit/cipher_modules/report_test.py \
  --ignore=tests/unit/ciphers/block_ciphers/qarmav2_with_mixcolumn_block_cipher_test.py \
  --ignore=tests/unit/ciphers/hash_functions/whirlpool_hash_function_test.py \
  tests/unit/

pytest:
	pytest -v -n=16 --dist loadfile tests/unit/ --randomly-seed=1553614239

github-pytest:
	pytest -v tests/unit/

pytest-coverage:
	pytest -v -n=2 --dist loadfile --cov-report term-missing --cov=$(PACKAGE) tests/unit/

benchmark-tests:
	pytest -v tests/benchmark/

testfast:
	$(SAGE_BIN) setup.py testfast

testall: install
	$(SAGE_BIN) setup.py testall

test: install
	SAGE_TIMEOUT=600 $(SAGE_BIN) -tp 32 $(MODULE)

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
