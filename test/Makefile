TOPDIR = $(realpath ..)

ifeq ($(GTEST_DIR),)
GTEST_DIR = /usr/src/googletest/googletest
endif

VPATH = $(TOPDIR)/src:$(TOPDIR)/src/nss:$(TOPDIR)/src/cache_refresh

TEST_RUNNER = ./test_runner --gtest_output=xml
CACHE_TEST_RUNNER = ./cache_test_runner --gtest_output=xml
SSHCA_TEST_RUNNER = ./sshca_runner --gtest_output=xml --gtest_filter="SSHCATests.*"
CPPFLAGS += -I$(TOPDIR)/src -I$(TOPDIR)/src/include -I/usr/include/json-c -I$(GTEST_DIR) -I$(GTEST_DIR)/../googlemock -isystem $(GTEST_DIR)/include -isystem $(GTEST_DIR)/../googlemock/include
CXXFLAGS += -g -Wall -Wextra
CFLAGS += -Wall -g -fPIC -Wstrict-prototypes -I$(TOPDIR)/src/include
LDLIBS = -lcurl -ljson-c -lpthread

.PHONY: all clean alltests ping reset
.PHONY: gtest prowtest non_network_tests network_tests
.DEFAULT_GOAL := all

all : test_runner non_network_tests

clean :
	rm -f test_runner test_detail.xml *.o

gtest-all.o: $(GTEST_DIR)/src/gtest-all.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $^

gmock-all.o: $(GTEST_DIR)/../googlemock/src/gmock-all.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $^

gtest_main.o: $(GTEST_DIR)/src/gtest_main.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $^

cache_test_runner: eytzinger_layout_test.o oslogin_passwd_cache_reader_test.o round_trip_test.o oslogin_passwd_cache_reader.o oslogin_passwd_cache_writer.o gtest-all.o gmock-all.o gtest_main.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

test_runner: oslogin_utils_test.o oslogin_utils.o gtest-all.o gtest_main.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

sshca_runner: oslogin_sshca_test.o $(TOPDIR)/src/oslogin_utils.o $(TOPDIR)/src/oslogin_sshca.o gtest-all.o gtest_main.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

sshca_tests: sshca_runner
	$(SSHCA_TEST_RUNNER)

non_network_tests: test_runner
	$(TEST_RUNNER) --gtest_filter=*-GetGroupByTest.*:GetUsersForGroupTest.*

network_tests: test_runner ping reset
	$(TEST_RUNNER) --gtest_filter=GetGroupByTest.*:GetUsersForGroupTest.*

# run as $ make tests GTESTARGS="--gtest_filter=GetGroupByTest.*"
alltests: test_runner cache_test_runner
	$(TEST_RUNNER) ${GTESTARGS}
	$(CACHE_TEST_RUNNER) ${GTESTARGS}

ping:
	nc -vzw2 169.254.169.254 80 >/dev/null 2>&1

reset:
	curl -Ss http://169.254.169.254/reset >/dev/null 2>&1
