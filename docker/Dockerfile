# Ubuntu 22.04
FROM ubuntu@sha256:3ba65aa20f86a0fad9df2b2c259c613df006b2e6d0bfcc8a146afb8c525a9751 AS claasp-base

ARG DEBIAN_FRONTEND=noninteractive
ARG COPY_CLAASP_LIBRARY=false
ARG INSTALL_CLAASP_LIBRARY=false
ARG TARGETARCH

# Install dependencies with apt-get
RUN apt-get -q update && \
    apt-get install --no-install-recommends -y \
    libboost-program-options-dev \
    libsqlite3-dev \
    libstdc++-9-dev \
    ca-certificates \
    gfortran \
    gcc \
    g++ \
    openssl \
    sudo \
    zlib1g-dev \
    autoconf \
    build-essential \
    cmake \
    git \
    gperf \
    wget \
    chromium-browser \
    chromium-chromedriver \
    dieharder=3.31.1.2-1build1 \
    latexmk=1:4.76-1 \
    python3-cryptominisat=5.8.0+dfsg1-2 \
    sagemath=9.5-4 \
    z3=4.8.12-1

COPY docker/sitecustomize.py /usr/lib/python3.10/sitecustomize.py

WORKDIR /opt

RUN set -eux; \
    cd /opt; \
    if [ "$TARGETARCH" = "arm64" ]; then \
        wget -q https://packages.gurobi.com/10.0/gurobi10.0.0_armlinux64.tar.gz; \
        tar -xzf gurobi10.0.0_armlinux64.tar.gz; \
        rm gurobi10.0.0_armlinux64.tar.gz; \
        ln -sfn /opt/gurobi1000/armlinux64 /opt/gurobi; \
    else \
        wget -q https://packages.gurobi.com/10.0/gurobi10.0.0_linux64.tar.gz; \
        tar -xzf gurobi10.0.0_linux64.tar.gz; \
        rm gurobi10.0.0_linux64.tar.gz; \
        ln -sfn /opt/gurobi1000/linux64 /opt/gurobi; \
    fi

ENV GUROBI_HOME=/opt/gurobi
ENV PATH="/opt/gurobi/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/gurobi/lib:${LD_LIBRARY_PATH}"

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
    && cmake -B build -S . \
    && cmake --build build -- -j4

ENV PATH="/opt/HiGHS/build/bin:${PATH}"

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
    gurobipy==11.0 \
    joblib==1.4.2 \
    kaleido==1.0.0 \
    keras==2.13.1 \
    minizinc==0.5.0 \
    networkx==2.8.8 \
    numpy==1.24.3 \
    pandas==1.5.2 \
    plotly==6.2.0 \
    prettytable==3.6.0 \
    progress==1.6 \
    psutil==7.1.3 \
    pycosat==0.6.3 \
    pygments==2.12.0 \
    pytest-benchmark==4.0.0 \
    pytest-cov==4.0.0 \
    pytest-isolate==0.0.14 \
    pytest-xdist==3.6.1 \
    pytest==7.2.1 \
    ruff==0.15.2 \
    sage-package==0.0.7 \
    setuptools==59.6.0 \
    sphinx==5.0.0 \
    sphinxcontrib-bibtex==2.5.0 \
    tensorflow==2.13.0

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
# No official Linux arm64 bundle exists for 2.9.4, so on arm64 we build from source
# and install under /MiniZinc to keep all downstream path references identical.
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        wget https://github.com/MiniZinc/libminizinc/archive/refs/tags/2.9.4.tar.gz \
        && tar -xf 2.9.4.tar.gz \
        && rm 2.9.4.tar.gz \
        && cmake -B libminizinc-2.9.4/build -S libminizinc-2.9.4 -DCMAKE_INSTALL_PREFIX=/MiniZinc \
        && cmake --build libminizinc-2.9.4/build -j$(nproc) \
        && cmake --install libminizinc-2.9.4/build \
        && rm -rf libminizinc-2.9.4; \
    else \
        wget https://github.com/MiniZinc/MiniZincIDE/releases/download/2.9.4/MiniZincIDE-2.9.4-bundle-linux-x86_64.tgz \
        && tar -xf MiniZincIDE-2.9.4-bundle-linux-x86_64.tgz \
        && mv MiniZincIDE-2.9.4-bundle-linux-x86_64 /MiniZinc \
        && rm MiniZincIDE-2.9.4-bundle-linux-x86_64.tgz; \
    fi

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

# Installing OR-Tools (CP-SAT backend for MiniZinc)
# Google ships one release tarball per platform; each already bundles a
# MiniZinc solver descriptor, but under an id/tags that don't match the
# "cp-sat" name claasp uses everywhere (see cipher_modules/models/cp/solvers.py),
# so we register our own descriptor pointing at the extracted files instead.
ARG ORTOOLS_VERSION=9.9.3963
RUN set -eux; \
    cd /opt; \
    if [ "$TARGETARCH" = "arm64" ]; then \
        wget -q "https://github.com/google/or-tools/releases/download/v9.9/or-tools_arm64_debian-11_cpp_v${ORTOOLS_VERSION}.tar.gz" -O or-tools.tar.gz; \
        tar -xzf or-tools.tar.gz; \
        rm or-tools.tar.gz; \
        mv "or-tools_aarch64_Debian-11_cpp_v${ORTOOLS_VERSION}" or-tools; \
    else \
        wget -q "https://github.com/google/or-tools/releases/download/v9.9/or-tools_amd64_ubuntu-22.04_cpp_v${ORTOOLS_VERSION}.tar.gz" -O or-tools.tar.gz; \
        tar -xzf or-tools.tar.gz; \
        rm or-tools.tar.gz; \
        mv "or-tools_x86_64_Ubuntu-22.04_cpp_v${ORTOOLS_VERSION}" or-tools; \
    fi; \
    cp /opt/or-tools/bin/fzn-cp-sat /usr/local/bin/; \
    chmod +x /usr/local/bin/fzn-cp-sat; \
    mkdir -p /usr/local/lib/or-tools; \
    cp /opt/or-tools/lib/*.so* /usr/local/lib/or-tools/; \
    echo "/usr/local/lib/or-tools" > /etc/ld.so.conf.d/or-tools.conf; \
    ldconfig; \
    mkdir -p /usr/local/share/minizinc/cpsat; \
    cp -r /opt/or-tools/share/minizinc/cpsat/* /usr/local/share/minizinc/cpsat/; \
    rm -rf /opt/or-tools

RUN mkdir -p /usr/local/share/minizinc/solvers \
  && printf '%s\n' \
  '{' \
  '  "name": "OR-Tools CP-SAT",' \
  "  \"version\": \"${ORTOOLS_VERSION}\"," \
  '  "id": "cp-sat",' \
  '  "executable": "/usr/local/bin/fzn-cp-sat",' \
  '  "mznlib": "/usr/local/share/minizinc/cpsat",' \
  '  "tags": ["cp-sat", "ortools", "cp", "int", "lcg"],' \
  '  "stdFlags": ["-a", "-f", "-p", "-r", "-s", "-v"],' \
  '  "supportsMzn": false,' \
  '  "supportsFzn": true,' \
  '  "needsSolns2Out": true,' \
  '  "needsMznExecutable": false,' \
  '  "needsStdlibDir": false,' \
  '  "isGUIApplication": false' \
  '}' > /usr/local/share/minizinc/solvers/cp-sat.msc

# Installing CryptoMiniSat
RUN wget https://github.com/msoos/cryptominisat/archive/refs/tags/release/v5.14.7.tar.gz \
    && tar -xf v5.14.7.tar.gz \
    && rm v5.14.7.tar.gz \
    && cd cryptominisat-release-v5.14.7 \
    && cmake -DENABLE_TESTING=OFF -DIPASIR=ON -B build -S . \
    && cmake --build build

ENV PATH="/opt/cryptominisat-release-v5.14.7/build/:${PATH}"

# Installing Kissat
RUN wget https://github.com/arminbiere/kissat/archive/refs/tags/rel-4.0.4.tar.gz \
    && tar -xf rel-4.0.4.tar.gz \
    && rm rel-4.0.4.tar.gz \
    && cd kissat-rel-4.0.4/ \
    && ./configure \
    && cd build/ \
    && make

ENV PATH="/opt/kissat-rel-4.0.4/build/:${PATH}"

# Installing Parkissat
RUN wget -O parkissat.tar.gz https://github.com/songfu1983/ParKissat-RS/archive/refs/heads/master.tar.gz \
    && ls / \
    && tar -xf parkissat.tar.gz \
    && rm parkissat.tar.gz

RUN cd ./ParKissat-RS-master/ \
    && make

ENV PATH="/opt/ParKissat-RS-master/:${PATH}"

# Installing Glucose
RUN git clone https://github.com/audemard/glucose.git glucose-syrup \
    && cd glucose-syrup \
    && git checkout 674dbba75b47864a332ba797bec80dcaca0a4857

RUN cd glucose-syrup/simp \
    && make

RUN cd glucose-syrup/parallel \
    && make

ENV PATH="/opt/glucose-syrup/simp:/opt/glucose-syrup/parallel:${PATH}"

# Installing MathSat (x86_64 only — no Linux arm64 binary available from the vendor)
RUN if [ "$TARGETARCH" != "arm64" ]; then \
        wget https://mathsat.fbk.eu/release/mathsat-5.6.11-linux-x86_64.tar.gz \
        && tar -xf mathsat-5.6.11-linux-x86_64.tar.gz \
        && rm mathsat-5.6.11-linux-x86_64.tar.gz \
        && ln -sf /opt/mathsat-5.6.11-linux-x86_64/bin/* /usr/local/bin/; \
    fi

# Installing Minisat
RUN wget https://github.com/stp/minisat/archive/refs/tags/releases/2.2.1.zip \
    && unzip 2.2.1.zip  \
    && rm 2.2.1.zip

RUN cd minisat-releases-2.2.1/  \
    && mkdir build && cd build \
    && cmake .. \
    && make

ENV PATH="/opt/minisat-releases-2.2.1/build:${PATH}"

# Installing Espresso
RUN wget https://github.com/classabbyamp/espresso-logic/archive/refs/tags/1.1.tar.gz \
    && tar -xf 1.1.tar.gz \
    && rm 1.1.tar.gz

RUN cd espresso-logic-1.1 \
    && cd espresso-src \
    && make

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
# The build output directory name is derived from the host triple (e.g.
# x86_64-pc-linux-gnu-release or aarch64-unknown-linux-gnu-release), so we
# symlink the built binaries into /usr/local/bin instead of hard-coding it.
RUN wget https://github.com/SRI-CSL/yices2/archive/refs/tags/yices-2.7.0.tar.gz \
    && tar -xf yices-2.7.0.tar.gz \
    && rm yices-2.7.0.tar.gz \
    && cd yices2-yices-2.7.0 \
    && autoconf \
    && ./configure --enable-thread-safety \
    && make -j4 \
    && ln -sf /opt/yices2-yices-2.7.0/build/*/dist/bin/* /usr/local/bin/

COPY required_dependencies/sage_numerical_backends_gurobi-9.3.1.tar.gz /opt/
RUN cd /opt/ && sage -pip install sage_numerical_backends_gurobi-9.3.1.tar.gz

RUN apt-get install -y coinor-cbc coinor-libcbc-dev
RUN sage -python -m pip install sage-numerical-backends-coin==9.0b12


FROM claasp-base AS claasp-lib

# Create a non-root user "sage" with home directory
ARG NAME=sage
RUN adduser --uid 1000 ${NAME} \
    && echo "sage ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN chown -R ${NAME}:${NAME} /usr/local/bin/sts-2.1.2

USER sage

WORKDIR /home/${NAME}/tii-claasp
COPY . .
RUN make install

ENV TERM=xterm-color
