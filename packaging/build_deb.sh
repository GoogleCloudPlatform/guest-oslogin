#!/bin/bash
# Copyright 2018 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

DEBIAN_FRONTEND=noninteractive
dpkg_working_dir="/tmp/debpackage"

. packaging/common.sh

DEB=$(cut -d. -f1 </etc/debian_version)
if [[ -z $DEB ]]; then
  echo "Can't determine debian version of build host"
  exit 1
fi

# Build dependencies.
echo "Installing dependencies."
try_command apt-get -y install make g++ libcurl4-openssl-dev libjson-c-dev \
  libpam-dev debhelper devscripts build-essential >/dev/null

dpkg-checkbuilddeps packaging/debian/control

echo "Building package"
[[ -d $dpkg_working_dir ]] && rm -rf $dpkg_working_dir
mkdir $dpkg_working_dir
tar czvf /tmp/debpackage/${PKGNAME}_${VERSION}.orig.tar.gz  --exclude .git \
  --exclude packaging --transform "s/^\./${PKGNAME}-${VERSION}/" .

working_dir=${PWD}
cd $dpkg_working_dir
tar xzvf ${PKGNAME}_${VERSION}.orig.tar.gz

cd ${PKGNAME}-${VERSION}

cp -r ${working_dir}/packaging/debian ./
echo "Building on Debian ${DEB}, modifying latest changelog entry."
sed -r -i"" "1s/^${PKGNAME} \((.*)\) (.+;.*)/${PKGNAME} (\1+deb${DEB}) \2/" \
  debian/changelog

DEB_BUILD_OPTIONS=noddebs debuild -us -uc
