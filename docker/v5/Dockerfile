# syntax=docker/dockerfile:1.7
FROM ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG TARGETARCH
ARG CHUFFED_VERSION=0.13.2
ARG CHUFFED_SHA256=39426a580690759ecf77ec5704caf5f2e21d41ff0aa09028827f5156bf5cb978
ARG NIST_STS_SHA256=0238d2f1d26e120e3cc748ed2d4c674cdc636de37fc4027c76cc2a394fff9157
ARG MSOLVE_VERSION=0.10.1
ARG MSOLVE_SHA256=ce0743cc33d1dc8484193268d9220e8624ed015e521903b9228b3b38a5981291
ARG KISSAT_VERSION=4.0.4
ARG KISSAT_SHA256=bfe93eaa6323b48011e4b1fcf74b3f2e20f9de544767e728009e5b2018296193
ARG HIGHS_VERSION=1.10.0
ARG HIGHS_SHA256=cf29873b894133bac111fc45bbf10989b6c5c041992fcd10e31222253e371a4c
ARG PARKISSAT_COMMIT=537bbea306846d1527d6024426ae361b0969c21a
ARG PARKISSAT_SHA256=bf065014833ab4dc1cc04ae7c70306605192e7b3f4bd6f4d71c5c7237ae89552
ARG GLUCOSE_VERSION=4.1
ARG GLUCOSE_SHA256=51aa1cf1bed2b14f1543b099e85a56dd1a92be37e6e3eb0c4a1fd883d5cc5029
ARG YICES_VERSION=2.6.4
ARG YICES_SHA256=533a24e020ecb7d64c03a965d598430d193651e2887e6f46924dec5786db78cb
ARG CHOCO_VERSION=4.10.18
ARG CHOCO_SOURCE_SHA256=9a6d8c465cc73752c085281f49c45793135d8545e57bc3f4effd15bde6d03de5
ARG CHOCO_JAR_SHA256=767a8bdf872c3b9d2a3465bb37822e1f0a60904a54f0181dbf7c6a106415abdf
ARG SOPLEX_VERSION=603
ARG SOPLEX_SHA256=2bdf9adc9ac6ad48f98056679b7b852e626ac4aaaf277e7d4ce17794ed1097be
ARG SCIP_VERSION=803
ARG SCIP_SHA256=fe7636f8165a8c9298ff55ed3220d084d4ea31ba9b69d2733beec53e0e4335d6
ARG ESPRESSO_VERSION=1.1
ARG ESPRESSO_SHA256=3e9ad0d7af29b67bc59c9bf014e9ed840af199490f1794b8249b4ab77f44b99e
# Ubuntu archive snapshot that the apt version pins below are resolved from.
# Bump it together with the pins; the live mirrors drop superseded versions.
ARG UBUNTU_SNAPSHOT=20261027T000000Z
ARG DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.title="CLAASP 5 release environment" \
      org.opencontainers.image.description="Pinned Sage-free multi-architecture validation environment" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/workspace/src \
    PATH=/opt/claasp-venv/bin:/usr/local/bin:/usr/bin:/bin

COPY docker/v5/install-packages.sh /usr/local/lib/claasp/install-packages.sh

# The snapshot service serves every architecture, ports included, under
# /ubuntu. It is HTTPS-only and the base image has no CA bundle yet, so TLS
# peer verification is skipped for that host alone; package integrity still
# rests on apt's signature check against the Ubuntu archive keyring.
# Retry transient snapshot-server errors without changing the pinned archive.
RUN printf 'Acquire::Retries "5";\nAcquire::https::Timeout "30";\n' \
        > /etc/apt/apt.conf.d/80-network-retries \
    && printf '%s\n' \
        'Types: deb' \
        "URIs: https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/" \
        'Suites: noble noble-updates noble-backports noble-security' \
        'Components: main universe restricted multiverse' \
        'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
        > /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get -q -o Acquire::https::snapshot.ubuntu.com::Verify-Peer=false \
        update --error-on=any \
    && sh /usr/local/lib/claasp/install-packages.sh \
        build-essential=12.10ubuntu1 \
        autoconf=2.71-3 \
        automake=1:1.16.5-1.3ubuntu1 \
        cadical=1.7.4-1 \
        ca-certificates=20260816ubuntu0.24.04.1 \
        cmake=3.28.3-1build7 \
        coinor-cbc=2.10.11+ds1-2 \
        cryptominisat=5.11.15+dfsg1-1.1build1 \
        curl=8.5.0-2ubuntu10.16 \
        dieharder=3.31.1.4-1.1build1 \
        git=1:2.43.0-1ubuntu7.4 \
        glpk-utils=5.0-1build2 \
        gperf=3.1-1build1 \
        minisat=1:2.2.1-8build1 \
        minizinc=2.8.2+dfsg1-1build2 \
        libflint-dev=3.0.1-3.1build1 \
        libcdd-tools=094m-1.1build1 \
        libgmp-dev=2:6.3.0+dfsg-2ubuntu6.1 \
        libtool=2.4.7-7build1 \
        openjdk-17-jre-headless=17.0.20.1+1-1~24.04 \
        python3=3.12.3-0ubuntu2.1 \
        python3-venv=3.12.3-0ubuntu2.1 \
        singular=1:4.3.2-p10+ds-1.1build1 \
        texlive-latex-base=2023.20240207-1 \
        texlive-pictures=2023.20240207-1 \
        unzip=6.0-28ubuntu4.1 \
        zlib1g-dev=1:1.3.dfsg-3.1ubuntu2.3 \
        z3=4.8.12-3.1build1 \
    && rm -rf /var/lib/apt/lists/*

COPY docker/v5/minizinc-wrapper.sh /usr/local/bin/minizinc
RUN sed -i 's/\r$//' /usr/local/bin/minizinc \
    && chmod 0755 /usr/local/bin/minizinc

COPY docker/v5/choco.msc /usr/local/share/minizinc/solvers/choco.msc
RUN set -eux; \
    curl -fsSL "https://codeload.github.com/chocoteam/choco-solver/tar.gz/refs/tags/v${CHOCO_VERSION}" \
        -o /tmp/choco-source.tar.gz; \
    echo "${CHOCO_SOURCE_SHA256}  /tmp/choco-source.tar.gz" | sha256sum -c -; \
    curl -fsSL \
        "https://github.com/chocoteam/choco-solver/releases/download/v${CHOCO_VERSION}/choco-solver-${CHOCO_VERSION}-light.jar" \
        -o /opt/choco-solver.jar; \
    echo "${CHOCO_JAR_SHA256}  /opt/choco-solver.jar" | sha256sum -c -; \
    tar -xzf /tmp/choco-source.tar.gz -C /tmp; \
    choco_source="/tmp/choco-solver-${CHOCO_VERSION}/parsers/src/main/minizinc"; \
    install -m 0755 "${choco_source}/fzn-choco.sh" /usr/local/bin/fzn-choco.sh; \
    install -m 0755 "${choco_source}/fzn-choco.py" /usr/local/bin/fzn-choco.py; \
    sed -i "s|^JAR_FILE=.*|JAR_FILE='/opt/choco-solver.jar'|" /usr/local/bin/fzn-choco.py; \
    mkdir -p /usr/local/share/minizinc/choco; \
    cp -a "${choco_source}/mzn_lib/." /usr/local/share/minizinc/choco/; \
    rm -rf /tmp/choco-source.tar.gz "/tmp/choco-solver-${CHOCO_VERSION}"; \
    minizinc --solvers | grep -i choco

WORKDIR /opt

RUN set -eux; \
    curl -fsSL \
        "https://github.com/arminbiere/kissat/archive/refs/tags/rel-${KISSAT_VERSION}.tar.gz" \
        -o kissat.tar.gz; \
    echo "${KISSAT_SHA256}  kissat.tar.gz" | sha256sum -c -; \
    tar -xzf kissat.tar.gz; \
    cd "kissat-rel-${KISSAT_VERSION}"; \
    ./configure; \
    make --jobs="$(nproc)"; \
    install -m 0755 build/kissat /usr/local/bin/kissat; \
    kissat --version; \
    cd /opt; \
    rm -rf kissat.tar.gz "kissat-rel-${KISSAT_VERSION}"

RUN set -eux; \
    curl -fsSL "https://codeload.github.com/ERGO-Code/HiGHS/tar.gz/refs/tags/v${HIGHS_VERSION}" -o highs.tar.gz; \
    echo "${HIGHS_SHA256}  highs.tar.gz" | sha256sum -c -; \
    tar -xzf highs.tar.gz; \
    cmake -S "HiGHS-${HIGHS_VERSION}" -B "HiGHS-${HIGHS_VERSION}/build" \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DFAST_BUILD=ON; \
    cmake --build "HiGHS-${HIGHS_VERSION}/build" --parallel "$(nproc)"; \
    cmake --install "HiGHS-${HIGHS_VERSION}/build"; \
    command -v highs; \
    rm -rf highs.tar.gz "HiGHS-${HIGHS_VERSION}"

RUN set -eux; \
    curl -fsSL "https://codeload.github.com/songfu1983/ParKissat-RS/tar.gz/${PARKISSAT_COMMIT}" \
        -o parkissat.tar.gz; \
    echo "${PARKISSAT_SHA256}  parkissat.tar.gz" | sha256sum -c -; \
    tar -xzf parkissat.tar.gz; \
    make -C "ParKissat-RS-${PARKISSAT_COMMIT}" --jobs="$(nproc)"; \
    install -m 0755 "ParKissat-RS-${PARKISSAT_COMMIT}/parkissat" /usr/local/bin/parkissat; \
    rm -rf parkissat.tar.gz "ParKissat-RS-${PARKISSAT_COMMIT}"

RUN set -eux; \
    curl -fsSL "https://www.labri.fr/perso/lsimon/downloads/softwares/glucose-syrup-${GLUCOSE_VERSION}.tgz" \
        -o glucose.tar.gz; \
    echo "${GLUCOSE_SHA256}  glucose.tar.gz" | sha256sum -c -; \
    tar -xzf glucose.tar.gz; \
    sed -i 's/#if defined(__linux__)/#if defined(__linux__) \&\& (defined(__i386__) || defined(__x86_64__))/' \
        "glucose-syrup-${GLUCOSE_VERSION}/simp/Main.cc" \
        "glucose-syrup-${GLUCOSE_VERSION}/parallel/Main.cc"; \
    cd "glucose-syrup-${GLUCOSE_VERSION}/simp"; \
    make --jobs="$(nproc)"; \
    cd ../parallel; \
    make --jobs="$(nproc)"; \
    cd /opt; \
    install -m 0755 "glucose-syrup-${GLUCOSE_VERSION}/simp/glucose" /usr/local/bin/glucose; \
    install -m 0755 "glucose-syrup-${GLUCOSE_VERSION}/parallel/glucose-syrup" \
        /usr/local/bin/glucose-syrup; \
    rm -rf glucose.tar.gz "glucose-syrup-${GLUCOSE_VERSION}"

RUN set -eux; \
    curl -fsSL "https://yices.csl.sri.com/releases/${YICES_VERSION}/yices-${YICES_VERSION}-src.tar.gz" \
        -o yices.tar.gz; \
    echo "${YICES_SHA256}  yices.tar.gz" | sha256sum -c -; \
    tar -xzf yices.tar.gz; \
    cd "yices2-Yices-${YICES_VERSION}"; \
    autoconf; \
    ./configure --prefix=/usr/local; \
    make --jobs="$(nproc)"; \
    make install; \
    /sbin/ldconfig; \
    command -v yices-sat; \
    command -v yices-smt2; \
    cd /opt; \
    rm -rf yices.tar.gz "yices2-Yices-${YICES_VERSION}"

RUN set -eux; \
    curl -fsSL "https://codeload.github.com/scipopt/soplex/tar.gz/refs/tags/release-${SOPLEX_VERSION}" \
        -o soplex.tar.gz; \
    echo "${SOPLEX_SHA256}  soplex.tar.gz" | sha256sum -c -; \
    tar -xzf soplex.tar.gz; \
    cmake -S "soplex-release-${SOPLEX_VERSION}" -B "soplex-release-${SOPLEX_VERSION}/build" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local; \
    cmake --build "soplex-release-${SOPLEX_VERSION}/build" --parallel "$(nproc)"; \
    cmake --install "soplex-release-${SOPLEX_VERSION}/build"; \
    /sbin/ldconfig; \
    rm -rf soplex.tar.gz "soplex-release-${SOPLEX_VERSION}"

RUN set -eux; \
    curl -fsSL "https://codeload.github.com/scipopt/scip/tar.gz/refs/tags/v${SCIP_VERSION}" \
        -o scip.tar.gz; \
    echo "${SCIP_SHA256}  scip.tar.gz" | sha256sum -c -; \
    tar -xzf scip.tar.gz; \
    cmake -S "scip-${SCIP_VERSION}" -B "scip-${SCIP_VERSION}/build" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DSOPLEX_DIR=/usr/local -DAUTOBUILD=ON -DBUILD_TESTING=OFF; \
    cmake --build "scip-${SCIP_VERSION}/build" --parallel "$(nproc)"; \
    cmake --install "scip-${SCIP_VERSION}/build"; \
    /sbin/ldconfig; \
    command -v scip; \
    rm -rf scip.tar.gz "scip-${SCIP_VERSION}"

ARG MATHSAT_VERSION=5.6.20
ARG MATHSAT_AMD64_SHA256=ca7d91b39b9934a00c4410057076c5a5029836a8a693206bfbbc968c52daa91e
ARG MATHSAT_ARM64_SHA256=38e96b8fb5a62f633cfaa1d4937f76d4d8156bd9a785e30ea12724110d75b589
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) mathsat_arch=x86_64; mathsat_sha="${MATHSAT_AMD64_SHA256}" ;; \
        arm64) mathsat_arch=aarch64; mathsat_sha="${MATHSAT_ARM64_SHA256}" ;; \
        *) echo "unsupported MathSAT architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mathsat_dir="mathsat-${MATHSAT_VERSION}-linux-${mathsat_arch}"; \
    curl -fsSL "https://mathsat.fbk.eu/release/${mathsat_dir}.tar.gz" -o mathsat.tar.gz; \
    echo "${mathsat_sha}  mathsat.tar.gz" | sha256sum -c -; \
    tar -xzf mathsat.tar.gz "${mathsat_dir}/bin/mathsat" "${mathsat_dir}/LICENSE.txt"; \
    install -m 0755 "${mathsat_dir}/bin/mathsat" /usr/local/bin/mathsat; \
    install -Dm 0644 "${mathsat_dir}/LICENSE.txt" /usr/local/share/licenses/mathsat/LICENSE.txt; \
    mathsat -version; \
    rm -rf mathsat.tar.gz "${mathsat_dir}"

ARG GUROBI_VERSION=13.0.2
ARG GUROBI_AMD64_SHA256=cffd4ee3c1990294e80446626bd1772045e420d7c34c379839b6acca16f0a23b
ARG GUROBI_ARM64_SHA256=3c50a31e20af6d7f815f0c77cad0461320bb5d1cd060c1f03d459a5b9b69c7ee
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) gurobi_arch=linux64; gurobi_sha="${GUROBI_AMD64_SHA256}" ;; \
        arm64) gurobi_arch=armlinux64; gurobi_sha="${GUROBI_ARM64_SHA256}" ;; \
        *) echo "unsupported Gurobi architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    gurobi_release="$(printf '%s' "${GUROBI_VERSION}" | tr -d '.')"; \
    gurobi_dir="gurobi${gurobi_release}/${gurobi_arch}"; \
    curl -fsSL \
        "https://packages.gurobi.com/13.0/gurobi${GUROBI_VERSION}_${gurobi_arch}.tar.gz" \
        -o gurobi.tar.gz; \
    echo "${gurobi_sha}  gurobi.tar.gz" | sha256sum -c -; \
    tar -xzf gurobi.tar.gz \
        "${gurobi_dir}/bin/gurobi_cl" \
        "${gurobi_dir}/lib/libgurobi.so.${GUROBI_VERSION}" \
        "${gurobi_dir}/EULA.pdf" \
        "${gurobi_dir}/licenses"; \
    install -m 0755 "${gurobi_dir}/bin/gurobi_cl" /usr/local/bin/gurobi_cl; \
    install -m 0755 "${gurobi_dir}/lib/libgurobi.so.${GUROBI_VERSION}" \
        "/usr/local/lib/libgurobi.so.${GUROBI_VERSION}"; \
    ln -s "libgurobi.so.${GUROBI_VERSION}" /usr/local/lib/libgurobi130.so; \
    mkdir -p /usr/local/share/licenses/gurobi; \
    cp -a "${gurobi_dir}/licenses/." /usr/local/share/licenses/gurobi/; \
    install -m 0644 "${gurobi_dir}/EULA.pdf" /usr/local/share/licenses/gurobi/EULA.pdf; \
    /sbin/ldconfig; \
    gurobi_cl --version; \
    rm -rf gurobi.tar.gz "gurobi${gurobi_release}"

RUN set -eux; \
    curl -fsSL \
        "https://github.com/classabbyamp/espresso-logic/archive/refs/tags/${ESPRESSO_VERSION}.tar.gz" \
        -o espresso.tar.gz; \
    echo "${ESPRESSO_SHA256}  espresso.tar.gz" | sha256sum -c -; \
    tar -xzf espresso.tar.gz; \
    make -C "espresso-logic-${ESPRESSO_VERSION}/espresso-src" --jobs="$(nproc)"; \
    install -m 0755 "espresso-logic-${ESPRESSO_VERSION}/bin/espresso" /usr/local/bin/espresso; \
    espresso -h >/dev/null 2>&1 || test "$?" -eq 1; \
    rm -rf espresso.tar.gz "espresso-logic-${ESPRESSO_VERSION}"

RUN set -eux; \
    curl -fsSL \
        "https://github.com/algebraic-solving/msolve/archive/refs/tags/v${MSOLVE_VERSION}.tar.gz" \
        -o msolve.tar.gz; \
    echo "${MSOLVE_SHA256}  msolve.tar.gz" | sha256sum -c -; \
    tar -xzf msolve.tar.gz; \
    cd "msolve-${MSOLVE_VERSION}"; \
    ./autogen.sh; \
    if [ "${TARGETARCH}" = amd64 ]; then \
        for extension in \
            rdrnd bmi1 bmi2 adx prefetchwt1 abm \
            sse3 ssse3 sse41 sse42 sse4a sha aes \
            avx fma3 fma4 xop avx2 \
            avx512f avx512cd avx512pf avx512er \
            avx512vl avx512bw avx512dq avx512ifma avx512vbmi; \
        do \
            eval "export ax_cv_have_${extension}_cpu_ext=no"; \
        done; \
    fi; \
    ./configure --prefix=/usr/local; \
    make --jobs="$(nproc)"; \
    make install; \
    /sbin/ldconfig; \
    cd /opt; \
    rm -rf msolve.tar.gz "msolve-${MSOLVE_VERSION}"

RUN set -eux; \
    curl -fsSL "https://github.com/chuffed/chuffed/archive/refs/tags/${CHUFFED_VERSION}.tar.gz" -o chuffed.tar.gz; \
    echo "${CHUFFED_SHA256}  chuffed.tar.gz" | sha256sum -c -; \
    tar -xzf chuffed.tar.gz; \
    cmake -B "chuffed-${CHUFFED_VERSION}/build" -S "chuffed-${CHUFFED_VERSION}" \
        -DCMAKE_BUILD_TYPE=Release; \
    cmake --build "chuffed-${CHUFFED_VERSION}/build" --parallel; \
    cmake --install "chuffed-${CHUFFED_VERSION}/build"; \
    rm -rf chuffed.tar.gz "chuffed-${CHUFFED_VERSION}"

COPY docker/v5/nist-patches/assess.c /tmp/nist-patches/assess.c
COPY docker/v5/nist-patches/utilities.c /tmp/nist-patches/utilities.c
COPY docker/v5/nist-patches/utilities.h /tmp/nist-patches/utilities.h

RUN set -eux; \
    curl -fsSL \
        https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip \
        -o sts.zip; \
    echo "${NIST_STS_SHA256}  sts.zip" | sha256sum -c -; \
    unzip -q sts.zip; \
    cp /tmp/nist-patches/assess.c sts-2.1.2/sts-2.1.2/src/; \
    cp /tmp/nist-patches/utilities.c sts-2.1.2/sts-2.1.2/src/; \
    cp /tmp/nist-patches/utilities.h sts-2.1.2/sts-2.1.2/include/; \
    make -C sts-2.1.2/sts-2.1.2; \
    mv sts-2.1.2/sts-2.1.2 /usr/local/bin/sts-2.1.2; \
    ln -s /usr/local/bin/sts-2.1.2/assess /usr/local/bin/niststs; \
    rm -rf sts.zip sts-2.1.2 /tmp/nist-patches

COPY docker/v5/requirements.lock /tmp/requirements.lock
RUN python3 -m venv /opt/claasp-venv \
    && python -m pip install --no-cache-dir --no-deps -r /tmp/requirements.lock \
    && python -m pip check \
    && rm /tmp/requirements.lock

COPY docker/v5/smoke.sh /usr/local/bin/claasp-release-smoke
RUN sed -i 's/\r$//' /usr/local/bin/claasp-release-smoke \
    && chmod 0755 /usr/local/bin/claasp-release-smoke \
    && /usr/local/bin/claasp-release-smoke

WORKDIR /workspace
CMD ["bash"]
