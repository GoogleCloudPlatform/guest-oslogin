all install :
	$(MAKE) -C src $@

alltests non_network_tests network_tests :
	$(MAKE) -C test $@

clean :
	$(MAKE) -C src clean
	$(MAKE) -C test clean

prowbuild : debian_deps all

prowtest : debian_deps non_network_tests
	mv test/test_detail.xml ${ARTIFACTS}/junit.xml

debian_deps :
	apt-get -y install g++ libcurl4-openssl-dev libjson-c-dev libpam-dev \
		googletest && touch $@

.PHONY : all clean install prowbuild prowtest alltests non_network_tests network_tests
