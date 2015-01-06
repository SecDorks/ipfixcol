# Docker image building script for running IPFIXcol in dedicated containers.
# It is assumed that three files are present on the same file system level
# as this file:
#
#   rs_intercfg.xml
#   rs_ipfix-elements.xml
#   rs_startup.xml
#
# These files will be copied to the container and used for configuring IPFIXcol.
# 
# You can build this image as follows:
#
#   docker build -t ipfixcol .
#       (Assumes the current working directory to be the directory with the Dockerfile)
#
# After building the image, which can easily take 15-30 minutes, a container (i.e.,
# instance of the image built previously) can be run as follows:
#
#   docker run -d -p 3055:3055/udp -p 3056:3056/tcp -v /var/db/rs-app/fastbit/:/var/db/rs-app/fastbit/ --name ipfixcol ipfixcol
#       (Once SCTP passthrough is supported by Docker, we add '-p 3057:3057/sctp' in the command above.
#           Feature request: https://github.com/docker/docker/issues/9689)
#
# The container can be stopped as follows:
#
#   docker stop ipfixcol
#
# The following command can be used for creating a snapshot of an IPFIXcol container,
# such that it can be deployed on other machines without the need of recompiling the
# source:
#
#   docker export ipfixcol > rs_ipfixcol_export.tar
#
# An exported container can be loaded into Docker as follows:
#
#   cat rs_ipfixcol_export.tar | sudo docker import - ipfixcol
#
# Container output (e.g., stdout and stderr) can be obtained as follows:
#
#   docker logs <container_id>
#
# Author:   Kirc <kirc&secdorks.net>
#

FROM ubuntu:14.04
MAINTAINER Kirc <kirc&secdorks.net>

WORKDIR /tmp/

# Install build dependencies
RUN apt-get update && apt-get install -y \
    autoconf \
    build-essential \
    git \
    libtool

# Install libfastbit
RUN git clone https://github.com/Secdorks/libfastbit.git
WORKDIR libfastbit/
RUN pwd
RUN autoreconf -if
RUN ./configure
RUN make
RUN make install
RUN ldconfig
WORKDIR /tmp/

# Install IPFIXcol
RUN apt-get update && apt-get install -y \
    bison \
    docbook-xsl \
    doxygen \
    flex \
    libsctp-dev \
    libssl-dev \
    libxml2-dev \
    pkg-config \
    xsltproc
RUN git clone https://github.com/Secdorks/ipfixcol.git
WORKDIR ipfixcol/base/
RUN autoreconf -if
RUN ./configure
RUN make
RUN make install
WORKDIR /tmp/

# Install httpfieldmerge (intermediate) plugin for IPFIXcol
WORKDIR ipfixcol/plugins/intermediate/httpfieldmerge/
RUN autoreconf -if
RUN ./configure
RUN make
RUN make install
WORKDIR /tmp/

# Install proxy (intermediate) plugin for IPFIXcol
# RUN apt-get update && apt-get install -y libc-ares-dev
# WORKDIR ipfixcol/plugins/intermediate/proxy/
# RUN autoreconf -if
# RUN ./configure
# RUN make
# RUN make install
# WORKDIR /tmp/

# Install FastBit (storage) plugin for IPFIXcol
WORKDIR ipfixcol/plugins/storage/fastbit/
RUN autoreconf -if
RUN ./configure
RUN make
RUN make install
WORKDIR /tmp/

# Install fbitdump
# WORKDIR ipfixcol/tools/fbitdump/
# RUN autoreconf -if
# RUN ./configure
# RUN make; make install
# WORKDIR /tmp/

# Clean up temporary files (used for building IPFIXcol)
RUN apt-get clean
RUN rm -r *

# Create directory for IPFIXcol config files
RUN mkdir /etc/ipfixcol

# Add IPFIXcol config files
COPY rs_internalcfg.xml /etc/ipfixcol/
COPY rs_ipfix-elements.xml /etc/ipfixcol/
COPY rs_startup.xml /etc/ipfixcol/

# Create dedicated user for running IPFIXcol
RUN adduser ipfixcol --uid 1010 --no-create-home --disabled-password --disabled-login --gecos ""

# Create directory for storing FastBit data
RUN mkdir -p /var/db/rs-app/fastbit/
RUN chown -R ipfixcol:ipfixcol /var/db/rs-app/fastbit/

# Run all subsequent commands as user 'ipfixcol'
USER ipfixcol

# Run IPFIXcol
CMD ["ipfixcol", "-c", "/etc/ipfixcol/rs_startup.xml", "-e", "/etc/ipfixcol/rs_ipfix-elements.xml", "-i", "/etc/ipfixcol/rs_internalcfg.xml"]

# Bind ports to host system
EXPOSE 3055
EXPOSE 3056
# EXPOSE 3057
