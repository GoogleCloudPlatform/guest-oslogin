#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <grp.h>
#include <nss.h>
#include <pwd.h>
#include <errno.h>
#include <stdint.h>

// Include the header to get the correct types.
#include "../src/include/oslogin_passwd_cache_reader.h"

extern "C" {
enum nss_status _nss_cache_oslogin_getgrgid_r(gid_t gid, struct group *result,
                                              char *buffer, size_t buflen,
                                              int *errnop);
}

extern "C" {
// Implement the mocked functions.
PasswdCache* open_passwd_cache(const char* filename) {
  return reinterpret_cast<PasswdCache*>(0x1234);
}

void close_passwd_cache(PasswdCache* cache) {}

struct passwd mock_user;
enum nss_status mock_lookup_status = NSS_STATUS_SUCCESS;

enum nss_status lookup_passwd_by_uid_r(PasswdCache* cache, uid_t uid,
                                       struct passwd* result, char* buffer,
                                       size_t buflen, int* errnop) {
  if (mock_lookup_status == NSS_STATUS_SUCCESS) {
    *result = mock_user;
  }
  return mock_lookup_status;
}

// Additional stubs to fix linker errors.
void passwd_cache_iter_begin(PasswdCache* cache, PasswdCacheIter* iter) {}

enum nss_status passwd_cache_iter_next_r(PasswdCache* cache,
                                         PasswdCacheIter* iter,
                                         struct passwd* result, char* buffer,
                                         size_t buflen, int* errnop) {
  return NSS_STATUS_NOTFOUND;
}

enum nss_status lookup_passwd_by_name_r(PasswdCache* cache, const char* name,
                                        struct passwd* result, char* buffer,
                                        size_t buflen, int* errnop) {
  return NSS_STATUS_NOTFOUND;
}
}

class NssCacheOsloginTest : public ::testing::Test {
 protected:
  void SetUp() override {
    mock_lookup_status = NSS_STATUS_SUCCESS;
    memset(&mock_user, 0, sizeof(mock_user));
  }
};

TEST_F(NssCacheOsloginTest, GetgrgidSelfGroupBufferTooSmall) {
  static char username[] = "testuser";
  mock_user.pw_name = username;
  mock_user.pw_uid = 1001;
  mock_user.pw_gid = 1001;

  struct group result;
  char buffer[1];
  int errnop = 0;
  
  enum nss_status status = _nss_cache_oslogin_getgrgid_r(1001, &result, buffer, sizeof(buffer), &errnop);
  
  EXPECT_EQ(status, NSS_STATUS_TRYAGAIN);
  EXPECT_EQ(errnop, ERANGE);
}

TEST_F(NssCacheOsloginTest, GetgrgidSelfGroupSuccess) {
  static char username[] = "testuser";
  mock_user.pw_name = username;
  mock_user.pw_uid = 1001;
  mock_user.pw_gid = 1001;

  struct group result;
  char buffer[1024];
  int errnop = 0;
  
  enum nss_status status = _nss_cache_oslogin_getgrgid_r(1001, &result, buffer, sizeof(buffer), &errnop);
  
  EXPECT_EQ(status, NSS_STATUS_SUCCESS);
  EXPECT_STREQ(result.gr_name, "testuser");
  EXPECT_STREQ(result.gr_passwd, "x");
  EXPECT_EQ(result.gr_gid, 1001);
  EXPECT_STREQ(result.gr_mem[0], "testuser");
  EXPECT_TRUE(result.gr_mem[1] == NULL);
}
