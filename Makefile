all install :
	$(MAKE) -C src $@

tests :
	$(MAKE) -C test non_network_tests

clean :
	$(MAKE) -C src clean
	$(MAKE) -C test clean

prowbuild : debian_deps all

prowtest : debian_deps tests

debian_deps :
	apt-get -y install g++ libcurl4-openssl-dev libjson-c-dev libpam-dev \
		googletest && touch $@

.PHONY : all clean install prowbuild prowtest
