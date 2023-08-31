.PHONY: all clean install
.PHONY: prowbuild prowtest
.PHONY: alltests non_network_tests network_tests

.DEFAULT_GOAL := all

all install: selinux_module
	$(MAKE) -C src $@

selinux_module:
ifdef INSTALL_SELINUX
	$(MAKE) -C selinux
else
	@echo "Variable INSTALL_SELINUX not defined, skipping selinux module build."
endif

alltests non_network_tests network_tests:
	$(MAKE) -C test $@

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
	rm -f debian_deps debian_build_deps debian_test_deps
	rm -f rhel_deps rhel_build_deps

prowbuild: debian_build_deps all

prowtest: debian_deps non_network_tests
	mv -f test/test_detail.xml ${ARTIFACTS}/junit.xml

debian_deps: debian_build_deps debian_test_deps
	touch $@

debian_build_deps:
	apt-get -y install g++ libcurl4-openssl-dev libjson-c-dev libpam-dev \
	&& touch $@

debian_test_deps:
	apt-get -y install googletest \
	&& touch $@

rhel_deps: rhel_build_deps
	touch $@

rhel_build_deps:
	dnf config-manager --set-enabled crb \
	&& dnf install -y policycoreutils gcc-c++ boost-devel libcurl-devel \
					json-c-devel pam-devel policycoreutils \
	&& touch $@
