#include <gtest/gtest.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <thread>
#include <string>
#include <vector>

// Globals to hold the in-memory mock file contents.
std::string mock_passwd_data;
std::string mock_group_data;

// Forward declaration of the interceptor function.
extern "C" FILE* mock_fopen(const char* path, const char* mode);

// Redefine fopen to call our interceptor. This will affect the included C file.
#define fopen(path, mode) mock_fopen(path, mode)

extern "C" {
#include "nss_cache_oslogin.c"
#include "include/compat.h"
}

// Undefine fopen so subsequent code in this file uses standard fopen if needed.
#undef fopen

// Implementation of the interceptor.
FILE* mock_fopen(const char* path, const char* mode) {
  // Check for the hardcoded production paths.
  if (strcmp(path, "/etc/oslogin_passwd.cache") == 0) {
    return fmemopen((void*)mock_passwd_data.data(), mock_passwd_data.size(), "r");
  }
  if (strcmp(path, "/etc/oslogin_group.cache") == 0) {
    return fmemopen((void*)mock_group_data.data(), mock_group_data.size(), "r");
  }
  // Fallback to standard library fopen for any other files.
  return ::fopen(path, mode);
}

class NssCacheTest : public ::testing::Test {
protected:
    /* Populate the in-memory buffers for the tests.
     * No actual files are written to disk, avoiding root permission requirements.
     */
    void SetUp() override {
        mock_passwd_data = 
            "testuser:x:1001:1001:Test User:/home/testuser:/bin/bash\n"
            "another:x:1002:1003:Another User:/home/another:/bin/sh\n"
            "upguser:x:1004:1004:UPG User:/home/upguser:/bin/bash\n";

        mock_group_data = 
            "testgroup:x:2001:testuser\n"
            "anothergroup:x:1003:\n"
            "nonupggroup:x:3000:\n";
    }

    void TearDown() override {
        mock_passwd_data.clear();
        mock_group_data.clear();
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
    enum nss_status status = _nss_cache_oslogin_getgrgid_r(1004, &result, buffer, BUFLEN, &errnop);
    ASSERT_EQ(status, NSS_STATUS_SUCCESS);
    ASSERT_STREQ(result.gr_name, "upguser");
    ASSERT_EQ(result.gr_gid, 1004);
}

TEST_F(NssCacheTest, BufferTooSmall) {
    struct passwd result;
    char small_buffer[5];
    enum nss_status status = _nss_cache_oslogin_getpwnam_r("testuser", &result, small_buffer, sizeof(small_buffer), &errnop);
    ASSERT_EQ(status, NSS_STATUS_TRYAGAIN);
    ASSERT_EQ(errnop, ERANGE);
}

TEST_F(NssCacheTest, GroupBufferTooSmall) {
    struct group result;
    char small_buffer[5];
    enum nss_status status = _nss_cache_oslogin_getgrgid_r(1004, &result, small_buffer, sizeof(small_buffer), &errnop);
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

/**
 * A regression test for non-UPG lookups.
 *
 * This test verifies that a lookup for a standard group (one that is not a
 * user-private group) succeeds. In the old code, this would have failed
 * because the getgrgid_r function was incorrectly registered to the passwd
 * database (NSDB_PASSWD, rather than NSDB_GROUP). The UPG check would fail, and
 * the subsequent logic to search the group file would never be reached because
 * glibc would not have called the function for a 'group' database query.
 */
TEST_F(NssCacheTest, GetGrGidForNonUPG) {
    struct group result;
    enum nss_status status = _nss_cache_oslogin_getgrgid_r(3000, &result, buffer, BUFLEN, &errnop);

    ASSERT_EQ(status, NSS_STATUS_SUCCESS);
    ASSERT_STREQ(result.gr_name, "nonupggroup");
    ASSERT_EQ(result.gr_gid, 3000);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
