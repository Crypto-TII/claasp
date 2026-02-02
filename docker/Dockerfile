FROM ubuntu:22.04 AS claasp-base

ARG DEBIAN_FRONTEND=noninteractive
ARG COPY_CLAASP_LIBRARY=false
ARG INSTALL_CLAASP_LIBRARY=false

# Install dependencies with apt-get
RUN apt-get -q update
RUN apt-get install --no-install-recommends -y \
  libboost-program-options-dev \
  libsqlite3-dev \
  libstdc++-9-dev \
  ca-certificates

RUN apt-get install --no-install-recommends -y \
  gfortran \
  gcc \
  g++

RUN apt-get install --no-install-recommends -y \
  openssl \
  sudo \
  zlib1g-dev

RUN apt-get install -y \
  build-essential \
  cmake \
  git \
  wget

RUN apt-get update && apt-get install -y \
  chromium-browser \
  chromium-chromedriver

RUN apt-get install -y \
  dieharder=3.31.1.2-1build1 \
  latexmk=1:4.76-1 \
  python3-cryptominisat=5.8.0+dfsg1-2 \
  sagemath=9.5-4 \
  z3=4.8.12-1

COPY docker/sitecustomize.py /usr/lib/python3.10/sitecustomize.py

WORKDIR /opt

RUN wget https://packages.gurobi.com/10.0/gurobi10.0.0_linux64.tar.gz \
    && tar -xf gurobi10.0.0_linux64.tar.gz \
    && rm gurobi10.0.0_linux64.tar.gz

ENV GUROBI_HOME="/opt/gurobi1000/linux64"
ENV PATH="${PATH}:${GUROBI_HOME}/bin"
ENV LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:${GUROBI_HOME}/lib"

WORKDIR /opt

# Installing Soplex (for SCIP)
RUN wget https://github.com/scipopt/soplex/archive/refs/tags/release-603.tar.gz \
    && tar -xf release-603.tar.gz \
    && rm release-603.tar.gz \
    && cd soplex-release-603 \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make

ENV SOPLEX_HOME="/opt/soplex-release-603/build"

# Installing HiGHS
RUN wget https://github.com/ERGO-Code/HiGHS/releases/download/v1.10.0/source-archive.tar.gz \
    && tar -xf source-archive.tar.gz \
    && rm source-archive.tar.gz \
    && cd HiGHS \
    && cmake -S. -B build \
    && cmake --build build

ENV PATH="${PATH}:/opt/HiGHS/build/bin"

WORKDIR /opt

# Installing TinyCThread for TPI support
RUN git clone --depth 1 https://github.com/tinycthread/tinycthread.git \
    && cd tinycthread \
    && mkdir build \
    && cd build \
    && cmake .. -DCMAKE_PREFIX_PATH=/usr/local \
    && make -j$(nproc) \
    && cp libtinycthread.a /usr/local/lib/ \
    && cp ../source/tinycthread.h /usr/local/include/ \
    && ldconfig

# Installing SCIP with TPI support for parallel solving using TinyCThread
RUN wget https://github.com/scipopt/scip/archive/refs/tags/v803.tar.gz \
    && tar -xf v803.tar.gz \
    && rm v803.tar.gz \
    && cd scip-803 \
    && mkdir build \
    && cd build \
    && cmake .. -DAUTOBUILD=on -DSOPLEX_DIR=${SOPLEX_HOME} -DTPI=tny -DCMAKE_PREFIX_PATH=/usr/local \
    && make -j$(nproc)

ENV PATH="${PATH}:/opt/scip-803/build/bin"
ENV LD_LIBRARY_PATH="/opt/scip-803/build/lib:/usr/local/lib:${LD_LIBRARY_PATH}"

# Installing SageMath tools
RUN sage -pip install bitstring==4.0.1 \
  kaleido==1.0.0 \
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
  plotly==6.2.0 \
  pytest==7.2.1 \
  pytest-cov==4.0.0 \
  pytest-xdist==3.2.0 \
  pytest-benchmark==4.0.0 \
  networkx==2.8.8 \
  numpy==1.24.3 \
  joblib==1.4.2 \
  gurobipy==11.0 \
  pytest-isolate==0.0.11 \
  psutil==7.1.3

# Installing nist sts
RUN curl -O -s https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip \
    && unzip sts-2_1_2.zip
COPY required_dependencies/assess.c /opt/sts-2.1.2/sts-2.1.2/src/
COPY required_dependencies/utilities.c /opt/sts-2.1.2/sts-2.1.2/src/
COPY required_dependencies/utilities.h /opt/sts-2.1.2/sts-2.1.2/include/
RUN cd /opt/sts-2.1.2/sts-2.1.2 \
    && make \
    && mv /opt/sts-2.1.2/sts-2.1.2 /usr/local/bin/ \
    && ln -s /usr/local/bin/sts-2.1.2/assess /usr/local/bin/niststs \
    && rm /opt/sts-2_1_2.zip

# Installing Minizinc
RUN wget https://github.com/MiniZinc/MiniZincIDE/releases/download/2.9.4/MiniZincIDE-2.9.4-bundle-linux-x86_64.tgz \
    && pwd && tar -xf MiniZincIDE-2.9.4-bundle-linux-x86_64.tgz 
RUN mv MiniZincIDE-2.9.4-bundle-linux-x86_64 /MiniZinc \
    && rm MiniZincIDE-2.9.4-bundle-linux-x86_64.tgz


# Copy all MiniZinc components to system locations
RUN cp /MiniZinc/bin/* /usr/local/bin/
RUN mkdir -p /usr/local/share/minizinc && cp -r /MiniZinc/share/minizinc/* /usr/local/share/minizinc/

RUN printf '%s\n' \
  '#!/bin/sh' \
  'export LD_LIBRARY_PATH=/MiniZinc/lib:"$LD_LIBRARY_PATH"' \
  'export SCIPOPTDIR=/opt/scip-803/build' \
  'export PATH="$SCIPOPTDIR/bin:$PATH"' \
  'export LD_LIBRARY_PATH="$SCIPOPTDIR/lib:$LD_LIBRARY_PATH"' \
  'exec /MiniZinc/bin/minizinc "$@"' \
  > /usr/local/bin/minizinc-wrapper \
  && chmod +x /usr/local/bin/minizinc-wrapper \
  && ln -sf /usr/local/bin/minizinc-wrapper /usr/local/bin/minizinc


# Installing Chuffed
RUN wget https://github.com/chuffed/chuffed/archive/refs/tags/0.13.2.tar.gz \
    && tar -xf 0.13.2.tar.gz \
    && rm 0.13.2.tar.gz

RUN cd chuffed-0.13.2 \
    && cmake -B build -S . \
    && cmake --build build \
    && cmake --build build --target install


# Installing Choco
WORKDIR /opt

RUN wget https://github.com/chocoteam/choco-solver/archive/refs/tags/v4.10.18.tar.gz \
    && tar -xf v4.10.18.tar.gz \
    && rm v4.10.18.tar.gz

RUN mv choco-solver-4.10.18/parsers/src/main/minizinc/fzn-choco* /usr/local/bin \
    && mkdir /usr/local/share/minizinc/choco \
    && mv choco-solver-4.10.18/parsers/src/main/minizinc/mzn_lib/* /usr/local/share/minizinc/choco

RUN wget https://github.com/chocoteam/choco-solver/releases/download/v4.10.18/choco-solver-4.10.18-light.jar

# Update files
RUN sed -i 's&JAR_FILE=.*&JAR_FILE="/opt/choco-solver-4.10.18-light.jar"&g' /usr/local/bin/fzn-choco.py

RUN echo '\
{\n\
  "name": "Choco-solver",\n\
  "version": "4.10.18",\n\
  "id": "org.choco.choco",\n\
  "executable": "/usr/local/bin/fzn-choco.sh",\n\
  "mznlib": "/usr/local/share/minizinc/choco",\n\
  "tags": ["cp","int"],\n\
  "stdFlags": ["-a","-n","-s","-p","-r","-f","-t","--cp-profiler"]\n\
}\
' > /usr/local/share/minizinc/solvers/choco.msc

# Installing CryptoMiniSat
# explicit commits are used instead of releases because
# no semantic versioning is used for cadical and cadiback
WORKDIR /opt

RUN git clone https://github.com/meelgroup/cadical.git \
    && cd cadical \
    && git checkout f5ac6ffa6eaaf72b407f6fb591091c5ff02271d8 \
    && CXXFLAGS=-fPIC ./configure --competition \
    && make -j4 \
    && cp build/libcadical.so /usr/lib/

RUN git clone https://github.com/meelgroup/cadiback.git \
    && cd cadiback \
    && git checkout 6050733173995f3cff6ecb04ac99d3691bd0b5e4 \
    && CXX=c++ ./configure \
    && make -j4 \
    && cp libcadiback.so /usr/lib/

RUN git clone https://github.com/msoos/cryptominisat.git \
    && cd cryptominisat \
    && git checkout 34ec41b3bb0332bd313e51d131298d30c52aa71f \
    && cmake -DENABLE_TESTING=OFF -DIPASIR=ON -B build -S . \
    && cmake --build build \
    && cmake --build build --target install

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
RUN git clone https://github.com/audemard/glucose.git glucose-syrup \
    && cd glucose-syrup \
    && git checkout 674dbba75b47864a332ba797bec80dcaca0a4857

RUN cd glucose-syrup/simp \
    && make

RUN cd glucose-syrup/parallel \
    && make

WORKDIR /opt

ENV PATH="/opt/glucose-syrup/simp:/opt/glucose-syrup/parallel:${PATH}"

# Installing MathSat
RUN wget https://mathsat.fbk.eu/release/mathsat-5.6.11-linux-x86_64.tar.gz \
    && tar -xf mathsat-5.6.11-linux-x86_64.tar.gz \
    && rm mathsat-5.6.11-linux-x86_64.tar.gz

ENV PATH="/opt/mathsat-5.6.11-linux-x86_64/bin:${PATH}"

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

ENV PATH="/opt/cadical-rel-1.5.3/build:${PATH}"

# Installing Yices
WORKDIR /opt

RUN wget https://yices.csl.sri.com/releases/2.6.4/yices-2.6.4-x86_64-pc-linux-gnu.tar.gz  \
    && tar -xf yices-2.6.4-x86_64-pc-linux-gnu.tar.gz \
    && rm yices-2.6.4-x86_64-pc-linux-gnu.tar.gz

RUN cd yices-2.6.4 \
    && ./install-yices

COPY required_dependencies/sage_numerical_backends_gurobi-9.3.1.tar.gz /opt/
RUN cd /opt/ && sage -pip install sage_numerical_backends_gurobi-9.3.1.tar.gz

RUN apt-get install -y coinor-cbc coinor-libcbc-dev
RUN sage -python -m pip install sage-numerical-backends-coin==9.0b12

# clean image
RUN rm -r /opt/choco-solver-4.10.18
RUN rm -r /opt/chuffed-0.13.2


FROM claasp-base AS claasp-lib

# Create a non-root user "sage" with home directory
ARG NAME=sage
RUN adduser --uid 1000 ${NAME} \
    && echo "sage ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN chown -R ${NAME}:${NAME} /usr/local/bin/sts-2.1.2
RUN pip install ruff --prefix /usr

USER sage

WORKDIR /home/${NAME}/tii-claasp
COPY . .
RUN make install

ENV TERM=xterm-color
