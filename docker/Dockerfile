FROM ubuntu:22.04 AS claasp-base

ARG DEBIAN_FRONTEND=noninteractive
ARG COPY_CLAASP_LIBRARY=false
ARG INSTALL_CLAASP_LIBRARY=false

# Install dependencies with apt-get
RUN apt-get -qq update
RUN apt-get install --no-install-recommends -y gfortran \
  gcc \
  g++ \
  libboost-program-options-dev \
  libsqlite3-dev \
  libstdc++-9-dev \
  openssl \
  sudo \
  zlib1g-dev
RUN apt-get install -y build-essential \
  cmake \
  dieharder=3.31.1.2-1build1 \
  git \
  latexmk=1:4.76-1 \
  python3-cryptominisat=5.8.0+dfsg1-2 \
  sagemath=9.5-4 \
  wget \
  z3

COPY docker/sitecustomize.py /usr/lib/python3.10/sitecustomize.py

WORKDIR /opt

RUN wget https://packages.gurobi.com/10.0/gurobi10.0.0_linux64.tar.gz \
    && tar -xf gurobi10.0.0_linux64.tar.gz \
    && rm gurobi10.0.0_linux64.tar.gz

ENV GUROBI_HOME="/opt/gurobi1000/linux64"
ENV PATH="${PATH}:${GUROBI_HOME}/bin"
ENV LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:${GUROBI_HOME}/lib"

WORKDIR /opt

## Installing Soplex (for SCIP)

RUN wget https://github.com/scipopt/soplex/archive/refs/tags/release-603.tar.gz \
    && tar -xf release-603.tar.gz \
    && rm release-603.tar.gz \
    && cd soplex-release-603 \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make

ENV SOPLEX_HOME="/opt/soplex-release-603/build"

WORKDIR /opt

## Installing SCIP
RUN wget https://github.com/scipopt/scip/archive/refs/tags/v803.tar.gz \
    && tar -xf v803.tar.gz \
    && rm v803.tar.gz \
    && cd scip-803 \
    && mkdir build \
    && cd build \
    && cmake .. -DAUTOBUILD=on -DSOPLEX_DIR=${SOPLEX_HOME} \
    && make

ENV PATH="${PATH}:/opt/scip-803/build/bin"

# Installing SageMath tools
RUN sage -pip install bitstring==4.0.1 \
  keras==2.13.1 \
  minizinc==0.5.0 \
  pandas==1.5.2 \
  prettytable==3.6.0 \
  progress==1.6 \
  pycosat==0.6.3 \
  pygments==2.12.0 \
  sage-package==0.0.7 \
  setuptools==59.6.0 \
  sphinx==5.0.0 \
  sphinxcontrib-bibtex==2.5.0 \
  tensorflow==2.13.0 \
  pytest==7.2.1 \
  pytest-cov==4.0.0 \
  pytest-xdist==3.2.0 \
  pytest-benchmark==4.0.0 \
  networkx==2.8.8 \
  numpy==1.24.3 \
  joblib==1.4.2 \
  gurobipy==11.0

# Installing nist sts
COPY required_dependencies/assess.c /opt/
COPY required_dependencies/utilities.c /opt/
COPY required_dependencies/utilities.h /opt/

RUN curl -O -s https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip \
    && unzip sts-2_1_2.zip
RUN mv /opt/assess.c /opt/sts-2.1.2/sts-2.1.2/src/
RUN mv /opt/utilities.c /opt/sts-2.1.2/sts-2.1.2/src/
RUN mv /opt/utilities.h /opt/sts-2.1.2/sts-2.1.2/include/
RUN cd /opt/sts-2.1.2/sts-2.1.2 \
    && make \
    && mv /opt/sts-2.1.2/sts-2.1.2 /usr/local/bin/ \
    && ln -s /usr/local/bin/sts-2.1.2/assess /usr/local/bin/niststs \
    && rm /opt/sts-2_1_2.zip

WORKDIR /opt

# Installing Minizinc
RUN wget https://github.com/MiniZinc/MiniZincIDE/releases/download/2.6.4/MiniZincIDE-2.6.4-bundle-linux-x86_64.tgz \
    && tar -xf MiniZincIDE-2.6.4-bundle-linux-x86_64.tgz \
    && rm MiniZincIDE-2.6.4-bundle-linux-x86_64.tgz

ENV PATH="/opt/MiniZincIDE-2.6.4-bundle-linux-x86_64/bin:${PATH}"

# Installing CryptoMiniSat
RUN wget https://github.com/msoos/cryptominisat/archive/refs/tags/5.11.4.tar.gz \
    && tar -xf 5.11.4.tar.gz \
    && rm 5.11.4.tar.gz

RUN cd cryptominisat-5.11.4 \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make \
    && make install \
    && ldconfig

WORKDIR /opt

# Installing Kissat
RUN wget https://github.com/arminbiere/kissat/archive/refs/tags/rel-3.0.0.tar.gz \
    && tar -xf rel-3.0.0.tar.gz \
    && rm rel-3.0.0.tar.gz

RUN cd kissat-rel-3.0.0/ \
    && ./configure \
    && cd build/ \
    && make

WORKDIR /opt

ENV PATH="/opt/kissat-rel-3.0.0/build/:${PATH}"

# Installing Parkissat
RUN wget -O parkissat.tar.gz https://github.com/songfu1983/ParKissat-RS/archive/refs/heads/master.tar.gz \
    && ls / \
    && tar -xf parkissat.tar.gz \
    && rm parkissat.tar.gz

RUN cd ./ParKissat-RS-master/ \
    && make

WORKDIR /opt

ENV PATH="/opt/ParKissat-RS-master/:${PATH}"

# Installing Glucose
RUN wget https://www.labri.fr/perso/lsimon/downloads/softwares/glucose-syrup-4.1.tgz  \
    && tar -xf glucose-syrup-4.1.tgz \
    && rm glucose-syrup-4.1.tgz

RUN cd glucose-syrup-4.1/simp \
    && make

RUN cd glucose-syrup-4.1/parallel \
    && make

WORKDIR /opt

ENV PATH="/opt/glucose-syrup-4.1/simp:/opt/glucose-syrup-4.1/parallel:${PATH}"

# Installing MathSat
RUN wget https://mathsat.fbk.eu/download.php?file=mathsat-5.6.9-linux-x86_64.tar.gz \
    && mv download.php?file=mathsat-5.6.9-linux-x86_64.tar.gz mathsat-5.6.9-linux-x86_64.tar.gz \
    && tar -xf mathsat-5.6.9-linux-x86_64.tar.gz \
    && rm mathsat-5.6.9-linux-x86_64.tar.gz

ENV PATH="/opt/mathsat-5.6.9-linux-x86_64/bin:${PATH}"

# Installing Minisat
RUN wget https://github.com/stp/minisat/archive/refs/tags/releases/2.2.1.zip \
    && unzip 2.2.1.zip  \
    && rm 2.2.1.zip

RUN cd minisat-releases-2.2.1/  \
    && mkdir build && cd build \
    && cmake .. \
    && make

WORKDIR /opt

ENV PATH="/opt/minisat-releases-2.2.1/build:${PATH}"

# Installing Espresso
RUN wget https://github.com/classabbyamp/espresso-logic/archive/refs/tags/1.1.tar.gz \
    && tar -xf 1.1.tar.gz \
    && rm 1.1.tar.gz

RUN cd espresso-logic-1.1 \
    && cd espresso-src \
    && make

WORKDIR /opt

ENV PATH="/opt/espresso-logic-1.1/bin:${PATH}"

# Installing Cadical
RUN wget https://github.com/arminbiere/cadical/archive/refs/tags/rel-1.5.3.tar.gz \
    && tar -xf rel-1.5.3.tar.gz \
    && rm rel-1.5.3.tar.gz

RUN cd cadical-rel-1.5.3 \
    && ./configure \
    && make

WORKDIR /opt

ENV PATH="/opt/cadical-rel-1.5.3/build:${PATH}"

# Installing Yices-Sat
RUN wget https://yices.csl.sri.com/releases/2.6.4/yices-2.6.4-x86_64-pc-linux-gnu.tar.gz  \
    && tar -xf yices-2.6.4-x86_64-pc-linux-gnu.tar.gz \
    && rm yices-2.6.4-x86_64-pc-linux-gnu.tar.gz

RUN cd yices-2.6.4 \
    && ./install-yices

WORKDIR /opt

ENV MZN_SOLVER_PATH="/opt/minizinc/solvers"

ENV LD_LIBRARY_PATH="/opt/MiniZincIDE-2.6.4-bundle-linux-x86_64/lib:${LD_LIBRARY_PATH}"

RUN rm -rf /opt/MiniZincIDE-2.6.4-bundle-linux-x86_64/lib/liblzma.so.5
RUN rm -rf /opt/MiniZincIDE-2.6.4-bundle-linux-x86_64/lib/libselinux.so.1
RUN rm -rf /opt/MiniZincIDE-2.6.4-bundle-linux-x86_64/lib/libsystemd.so.0
RUN rm -rf /opt/MiniZincIDE-2.6.4-bundle-linux-x86_64/lib/libcrypt.so.1

RUN sage -pip install plotly -U kaleido
COPY required_dependencies/sage_numerical_backends_gurobi-9.3.1.tar.gz /opt/
RUN cd /opt/ && sage -pip install sage_numerical_backends_gurobi-9.3.1.tar.gz

RUN apt-get install -y coinor-cbc coinor-libcbc-dev
RUN sage -python -m pip install sage-numerical-backends-coin==9.0b12

WORKDIR /home/sage/tii-claasp

FROM claasp-base AS claasp-lib

COPY . .

RUN make install
