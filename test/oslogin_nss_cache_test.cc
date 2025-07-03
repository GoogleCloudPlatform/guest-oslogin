#include <gtest/gtest.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <thread>

// The C code to be tested needs to be included this way
extern "C" {
#include "nss_cache_oslogin.c"
#include "include/compat.h"
}

class NssCacheTest : public ::testing::Test {
protected:
    /* Create mock passwd and group files for tests.
     *
     * Note that using the hardcoded OSLOGIN_*_CACHE_PATH macros may cause file
     * permission issues, requiring us to run as root. Running these tests will
     * also wipe the OS Login cache (in case you're testing this on a GCE VM),
     * which should be largely harmless but is nonetheless a side-effect to be
     * aware of.
     *
     * If this proves to be a problem, then consider adding in a few functions
     * to nss_cache_oslogin.c to allow the cache paths to be overridden. */
    void SetUp() override {
        FILE* p_file = fopen(OSLOGIN_PASSWD_CACHE_PATH, "w");
        if (p_file == NULL) {
          perror("Failed to open passwd cache file");
        }
        ASSERT_NE(p_file, nullptr);
        fprintf(p_file, "testuser:x:1001:1001:Test User:/home/testuser:/bin/bash\n");
        fprintf(p_file, "another:x:1002:1003:Another User:/home/another:/bin/sh\n");
        // User with matching UID/GID for UPG tests.
        fprintf(p_file, "upguser:x:1004:1004:UPG User:/home/upguser:/bin/bash\n");
        fclose(p_file);

        FILE* g_file = fopen(OSLOGIN_GROUP_CACHE_PATH, "w");
        if (g_file == NULL) {
          perror("Failed to open group cache file");
        }
        ASSERT_NE(g_file, nullptr);
        fprintf(g_file, "testgroup:x:2001:testuser\n");
        fprintf(g_file, "anothergroup:x:1003:\n");
        fclose(g_file);
    }

    // Clean up the mock files.
    void TearDown() override {
        remove(OSLOGIN_PASSWD_CACHE_PATH);
        remove(OSLOGIN_GROUP_CACHE_PATH);
    }

    // Helper to allocate buffer for NSS functions.
    static constexpr size_t BUFLEN = 4096;
    char buffer[BUFLEN];
    int errnop;
};

TEST_F(NssCacheTest, GetPwUidSuccess) {
    struct passwd result;
    enum nss_status status = _nss_cache_oslogin_getpwuid_r(1001, &result, buffer, BUFLEN, &errnop);
    ASSERT_EQ(status, NSS_STATUS_SUCCESS);
    ASSERT_STREQ(result.pw_name, "testuser");
    ASSERT_EQ(result.pw_uid, 1001);
    ASSERT_EQ(result.pw_gid, 1001);
}

TEST_F(NssCacheTest, GetPwUidNotFound) {
    struct passwd result;
    enum nss_status status = _nss_cache_oslogin_getpwuid_r(9999, &result, buffer, BUFLEN, &errnop);
    ASSERT_EQ(status, NSS_STATUS_NOTFOUND);
}

TEST_F(NssCacheTest, GetGrGidForUPG) {
    struct group result;
    // For a UPG, getgrgid should succeed by finding the user in the passwd cache.
    //
    enum nss_status status = _nss_cache_oslogin_getgrgid_r(1004, &result, buffer, BUFLEN, &errnop);
    ASSERT_EQ(status, NSS_STATUS_SUCCESS);
    ASSERT_STREQ(result.gr_name, "upguser");
    ASSERT_EQ(result.gr_gid, 1004);
}

TEST_F(NssCacheTest, BufferTooSmall) {
    struct passwd result;
    char small_buffer[5];
    enum nss_status status = _nss_cache_oslogin_getpwnam_r("testuser", &result, small_buffer, sizeof(small_buffer), &errnop);
    // The function should report that the buffer is too small.
    //
    ASSERT_EQ(status, NSS_STATUS_TRYAGAIN);
    ASSERT_EQ(errnop, ERANGE);
}

TEST_F(NssCacheTest, EnumerateAllUsers) {
    struct passwd result;
    std::vector<std::string> users;

    _nss_cache_oslogin_setpwent(0);
    while (_nss_cache_oslogin_getpwent_r(&result, buffer, BUFLEN, &errnop) == NSS_STATUS_SUCCESS) {
        users.push_back(result.pw_name);
    }
    _nss_cache_oslogin_endpwent();

    ASSERT_EQ(users.size(), 3);
    ASSERT_EQ(users[0], "testuser");
    ASSERT_EQ(users[1], "another");
    ASSERT_EQ(users[2], "upguser");
}

/** A regression test for issue #160. */
TEST_F(NssCacheTest, InterleavedLookupDoesNotCorruptEnumerationState) {
    struct passwd pwent_result;
    struct passwd pwnam_result;
    char pwent_buffer[BUFLEN];
    char pwnam_buffer[BUFLEN];
    int errnop;

    // 1. Start the user enumeration process. This opens the passwd cache file
    //    and positions the cursor at the beginning.
    ASSERT_EQ(_nss_cache_oslogin_setpwent(0), NSS_STATUS_SUCCESS);

    // 2. Read the first entry ("testuser") from the enumeration.
    //    This advances the cursor to the second line.
    ASSERT_EQ(_nss_cache_oslogin_getpwent_r(&pwent_result, pwent_buffer, BUFLEN, &errnop), NSS_STATUS_SUCCESS);
    ASSERT_STREQ(pwent_result.pw_name, "testuser");

    // 3. Perform a lookup for a different user ("another"). In the old, buggy code,
    //    this call would reset the enumeration's file pointer back to the beginning.
    ASSERT_EQ(_nss_cache_oslogin_getpwnam_r("another", &pwnam_result, pwnam_buffer, BUFLEN, &errnop), NSS_STATUS_SUCCESS);
    ASSERT_STREQ(pwnam_result.pw_name, "another");

    // 4. Continue the enumeration. With the fix, the thread-local file pointer
    //    should be unaffected, and this call should read the *second* entry.
    //    If the bug still existed, this would incorrectly read the first entry again.
    ASSERT_EQ(_nss_cache_oslogin_getpwent_r(&pwent_result, pwent_buffer, BUFLEN, &errnop), NSS_STATUS_SUCCESS);
    ASSERT_STREQ(pwent_result.pw_name, "another"); // Verify we got the second user.

    // 5. Clean up the enumeration state.
    _nss_cache_oslogin_endpwent();
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
