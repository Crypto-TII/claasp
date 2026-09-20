# syntax=docker/dockerfile:1.7
FROM ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG TARGETARCH
ARG CHUFFED_VERSION=0.13.2
ARG CHUFFED_SHA256=39426a580690759ecf77ec5704caf5f2e21d41ff0aa09028827f5156bf5cb978
ARG NIST_STS_SHA256=0238d2f1d26e120e3cc748ed2d4c674cdc636de37fc4027c76cc2a394fff9157
ARG MSOLVE_VERSION=0.10.1
ARG MSOLVE_SHA256=ce0743cc33d1dc8484193268d9220e8624ed015e521903b9228b3b38a5981291
ARG DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.title="CLAASP 5 release environment" \
      org.opencontainers.image.description="Pinned Sage-free multi-architecture validation environment" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/workspace/src \
    PATH=/opt/claasp-venv/bin:/usr/local/bin:/usr/bin:/bin

RUN apt-get -q update \
    && apt-get install --no-install-recommends -y \
        build-essential=12.10ubuntu1 \
        autoconf=2.71-3 \
        automake=1:1.16.5-1.3ubuntu1 \
        ca-certificates=20260601~24.04.1 \
        cmake=3.28.3-1build7 \
        curl=8.5.0-2ubuntu10.13 \
        dieharder=3.31.1.4-1.1build1 \
        git=1:2.43.0-1ubuntu7.3 \
        glpk-utils=5.0-1build2 \
        minisat=1:2.2.1-8build1 \
        minizinc=2.8.2+dfsg1-1build2 \
        libflint-dev=3.0.1-3.1build1 \
        libgmp-dev=2:6.3.0+dfsg-2ubuntu6.1 \
        libtool=2.4.7-7build1 \
        python3=3.12.3-0ubuntu2.1 \
        python3-venv=3.12.3-0ubuntu2.1 \
        singular=1:4.3.2-p10+ds-1.1build1 \
        texlive-latex-base=2023.20240207-1 \
        texlive-pictures=2023.20240207-1 \
        unzip=6.0-28ubuntu4.1 \
        z3=4.8.12-3.1build1 \
    && rm -rf /var/lib/apt/lists/*

COPY docker/v5/minizinc-wrapper.sh /usr/local/bin/minizinc
RUN chmod 0755 /usr/local/bin/minizinc

WORKDIR /opt

RUN set -eux; \
    curl -fsSL \
        "https://github.com/algebraic-solving/msolve/archive/refs/tags/v${MSOLVE_VERSION}.tar.gz" \
        -o msolve.tar.gz; \
    echo "${MSOLVE_SHA256}  msolve.tar.gz" | sha256sum -c -; \
    tar -xzf msolve.tar.gz; \
    cd "msolve-${MSOLVE_VERSION}"; \
    ./autogen.sh; \
    ./configure --prefix=/usr/local; \
    make --jobs="$(nproc)"; \
    make check; \
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
RUN chmod 0755 /usr/local/bin/claasp-release-smoke \
    && claasp-release-smoke

WORKDIR /workspace
CMD ["bash"]
