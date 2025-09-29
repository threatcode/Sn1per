# Build stage for reducing final image size
FROM docker.io/kalilinux/kali-rolling:latest as builder

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Install build dependencies
RUN set -x && \
    echo 'deb http://http.kali.org/kali kali-rolling main contrib non-free' > /etc/apt/sources.list && \
    echo 'deb-src http://http.kali.org/kali kali-rolling main contrib non-free' >> /etc/apt/sources.list && \
    apt-get update -yqq && \
    apt-get install -yqq --no-install-recommends \
        git \
        ca-certificates \
        curl \
        gnupg \
        && rm -rf /var/lib/apt/lists/*

# Final stage
FROM docker.io/kalilinux/kali-rolling:latest

# Set metadata
LABEL org.opencontainers.image.title='Sn1per - Kali Linux' \
    org.opencontainers.image.description='Automated pentest framework for offensive security experts' \
    org.opencontainers.image.documentation='https://github.com/threatcode/Sn1per' \
    org.opencontainers.image.source='https://github.com/threatcode/Sn1per' \
    org.opencontainers.image.url='https://github.com/threatcode/Sn1per' \
    org.opencontainers.image.vendor='Sn1per Security' \
    org.opencontainers.image.licenses='GPL-3.0' \
    org.opencontainers.image.authors='@xer0dayz' \
    org.opencontainers.image.version='latest' \
    maintainer="@xer0dayz"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HOME=/home/sniper \
    PATH="${HOME}/.local/bin:${PATH}"

# Create non-root user and set up working directory
RUN set -x && \
    groupadd -r sniper && \
    useradd -r -g sniper -d ${HOME} -s /bin/bash sniper && \
    mkdir -p ${HOME} && \
    chown -R sniper:sniper ${HOME}

# Install system dependencies
RUN set -x && \
    echo 'deb http://http.kali.org/kali kali-rolling main contrib non-free' > /etc/apt/sources.list && \
    echo 'deb-src http://http.kali.org/kali kali-rolling main contrib non-free' >> /etc/apt/sources.list && \
    apt-get update -yqq && \
    apt-get install -yqq --no-install-recommends \
        git \
        bash \
        python3 \
        python3-pip \
        python3-setuptools \
        metasploit-framework \
        postgresql \
        postgresql-client \
        && rm -rf /var/lib/apt/lists/*

# Configure PostgreSQL for Metasploit
RUN set -x && \
    mkdir -p /var/run/postgresql && \
    chown -R postgres:postgres /var/run/postgresql && \
    chmod 2777 /var/run/postgresql && \
    sed -i 's/systemctl status ${PG_SERVICE}/service ${PG_SERVICE} status/g' /usr/bin/msfdb

# Switch to non-root user
USER sniper
WORKDIR ${HOME}

# Clone and install Sn1per
RUN set -x && \
    git clone --depth 1 https://github.com/threatcode/Sn1per.git ${HOME}/Sn1per && \
    cd ${HOME}/Sn1per && \
    chmod +x install.sh && \
    ./install.sh && \
    sniper -u force

# Set up volumes for persistent data
VOLUME ["${HOME}/.msf4", "${HOME}/.sniper"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD sniper --version || exit 1

# Default command
ENTRYPOINT ["sniper"]
CMD ["--help"]