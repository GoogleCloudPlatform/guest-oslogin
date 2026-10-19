#include <dlfcn.h>
#include <errno.h>
#include <gmock/gmock.h>
#include <grp.h>
#include <gtest/gtest.h>
#include <nss.h>
#include <pwd.h>
#include <stdint.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// Include the header to get the correct types.
#include "../src/include/oslogin_passwd_cache_reader.h"

extern "C" {
enum nss_status _nss_cache_oslogin_getgrgid_r(gid_t gid, struct group *result,
                                              char *buffer, size_t buflen,
                                              int *errnop);
enum nss_status _nss_cache_oslogin_getgrnam_r(const char* name,
                                              struct group* result,
                                              char* buffer, size_t buflen,
                                              int* errnop);
enum nss_status _nss_cache_oslogin_setpwent(int stayopen);
enum nss_status _nss_cache_oslogin_getpwent_r(struct passwd* result,
                                              char* buffer, size_t buflen,
                                              int* errnop);
enum nss_status _nss_cache_oslogin_endpwent(void);
enum nss_status _nss_cache_oslogin_getpwuid_r(uid_t uid, struct passwd* result,
                                              char* buffer, size_t buflen,
                                              int* errnop);
enum nss_status _nss_cache_oslogin_getpwnam_r(const char* name,
                                              struct passwd* result,
                                              char* buffer, size_t buflen,
                                              int* errnop);
enum nss_status _nss_cache_oslogin_setgrent(int stayopen);
enum nss_status _nss_cache_oslogin_getgrent_r(struct group* result,
                                              char* buffer, size_t buflen,
                                              int* errnop);
enum nss_status _nss_cache_oslogin_endgrent(void);
}

// Globals to hold in-memory mock file contents for legacy passwd cache.
static const char* mock_passwd_data = nullptr;
static bool use_mock_binary_cache = true;

extern "C" {
// Intercept fopen to serve in-memory legacy passwd cache data.
FILE* fopen(const char* path, const char* mode) {
  if (strcmp(path, "/etc/oslogin_passwd.cache") == 0 ||
      strcmp(path, "/usr/local/etc/oslogin_passwd.cache") == 0) {
    if (mock_passwd_data == nullptr || mock_passwd_data[0] == '\0') {
      errno = ENOENT;
      return nullptr;
    }
    return fmemopen(const_cast<char*>(mock_passwd_data),
                    strlen(mock_passwd_data), "r");
  }
  using FopenFn = FILE* (*)(const char*, const char*);
  static FopenFn real_fopen =
      reinterpret_cast<FopenFn>(dlsym(RTLD_NEXT, "fopen"));
  return real_fopen(path, mode);
}

// Implement the mocked functions.
PasswdCache* open_passwd_cache(const char* filename) {
  if (!use_mock_binary_cache) {
    return nullptr;
  }
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

// Global mock state for binary cache iteration.
static const struct passwd* g_iter_users = nullptr;
static size_t g_iter_users_count = 0;
static size_t g_iter_idx = 0;

void passwd_cache_iter_begin(PasswdCache* cache, PasswdCacheIter* iter) {
  g_iter_idx = 0;
}

enum nss_status passwd_cache_iter_next_r(PasswdCache* cache,
                                         PasswdCacheIter* iter,
                                         struct passwd* result, char* buffer,
                                         size_t buflen, int* errnop) {
  if (g_iter_users != nullptr && g_iter_idx < g_iter_users_count) {
    *result = g_iter_users[g_iter_idx++];
    return NSS_STATUS_SUCCESS;
  }
  return NSS_STATUS_NOTFOUND;
}

enum nss_status lookup_passwd_by_name_r(PasswdCache* cache, const char* name,
                                        struct passwd* result, char* buffer,
                                        size_t buflen, int* errnop) {
  if (mock_lookup_status == NSS_STATUS_SUCCESS) {
    *result = mock_user;
  }
  return mock_lookup_status;
}
}

class NssCacheOsloginTest : public ::testing::Test {
 protected:
  void SetUp() override {
    use_mock_binary_cache = true;
    mock_lookup_status = NSS_STATUS_SUCCESS;
    memset(&mock_user, 0, sizeof(mock_user));
    mock_passwd_data =
        "testuser:x:1001:1001:Test User:/home/testuser:/bin/bash\n"
        "another:x:1002:1003:Another User:/home/another:/bin/sh\n"
        "upguser:x:1004:1004:UPG User:/home/upguser:/bin/bash\n";
  }

  void TearDown() override {
    _nss_cache_oslogin_endpwent();
    _nss_cache_oslogin_endgrent();
    mock_passwd_data = nullptr;
    g_iter_users = nullptr;
    g_iter_users_count = 0;
  }

  static constexpr size_t BUFLEN = 4096;
  char buffer[BUFLEN];
  int errnop = 0;
};

TEST_F(NssCacheOsloginTest, GetgrgidSelfGroupBufferTooSmall) {
  static char username[] = "testuser";
  mock_user.pw_name = username;
  mock_user.pw_uid = 1001;
  mock_user.pw_gid = 1001;

  struct group result;
  char buffer[1];
  int errnop = 0;

  enum nss_status status = _nss_cache_oslogin_getgrgid_r(
      1001, &result, buffer, sizeof(buffer), &errnop);

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

  enum nss_status status = _nss_cache_oslogin_getgrgid_r(
      1001, &result, buffer, sizeof(buffer), &errnop);

  EXPECT_EQ(status, NSS_STATUS_SUCCESS);
  EXPECT_STREQ(result.gr_name, "testuser");
  EXPECT_STREQ(result.gr_passwd, "x");
  EXPECT_EQ(result.gr_gid, 1001);
  EXPECT_STREQ(result.gr_mem[0], "testuser");
  EXPECT_TRUE(result.gr_mem[1] == NULL);
}

TEST_F(NssCacheOsloginTest, GetgrgidNotFoundWhenUserMissing) {
  mock_lookup_status = NSS_STATUS_NOTFOUND;

  struct group result;
  char buffer[1024];
  int errnop = 0;

  enum nss_status status = _nss_cache_oslogin_getgrgid_r(
      1001, &result, buffer, sizeof(buffer), &errnop);

  EXPECT_EQ(status, NSS_STATUS_NOTFOUND);
}

TEST_F(NssCacheOsloginTest, GetgrnamSelfGroupBufferTooSmall) {
  static char username[] = "testuser";
  mock_user.pw_name = username;
  mock_user.pw_uid = 1001;
  mock_user.pw_gid = 1001;

  struct group result;
  char buffer[1];
  int errnop = 0;

  enum nss_status status = _nss_cache_oslogin_getgrnam_r(
      "testuser", &result, buffer, sizeof(buffer), &errnop);

  EXPECT_EQ(status, NSS_STATUS_TRYAGAIN);
  EXPECT_EQ(errnop, ERANGE);
}

TEST_F(NssCacheOsloginTest, GetgrnamSelfGroupSuccess) {
  static char username[] = "testuser";
  mock_user.pw_name = username;
  mock_user.pw_uid = 1001;
  mock_user.pw_gid = 1001;

  struct group result;
  char buffer[1024];
  int errnop = 0;

  enum nss_status status = _nss_cache_oslogin_getgrnam_r(
      "testuser", &result, buffer, sizeof(buffer), &errnop);

  EXPECT_EQ(status, NSS_STATUS_SUCCESS);
  EXPECT_STREQ(result.gr_name, "testuser");
  EXPECT_STREQ(result.gr_passwd, "x");
  EXPECT_EQ(result.gr_gid, 1001);
  EXPECT_STREQ(result.gr_mem[0], "testuser");
  EXPECT_TRUE(result.gr_mem[1] == NULL);
}

TEST_F(NssCacheOsloginTest, GetgrnamNotFoundWhenUserMissing) {
  mock_lookup_status = NSS_STATUS_NOTFOUND;

  struct group result;
  char buffer[1024];
  int errnop = 0;

  enum nss_status status = _nss_cache_oslogin_getgrnam_r(
      "nonexistent", &result, buffer, sizeof(buffer), &errnop);

  EXPECT_EQ(status, NSS_STATUS_NOTFOUND);
}

TEST_F(NssCacheOsloginTest, GetgrentReturnsNotFound) {
  struct group result;
  char buffer[1024];
  int errnop = 0;

  enum nss_status status =
      _nss_cache_oslogin_getgrent_r(&result, buffer, sizeof(buffer), &errnop);

  EXPECT_EQ(status, NSS_STATUS_NOTFOUND);
}

TEST_F(NssCacheOsloginTest, InterleavedBinaryIterationAndLookupSanity) {
  struct passwd u1;
  static char u1_name[] = "user1";
  u1.pw_name = u1_name;
  u1.pw_uid = 1001;
  u1.pw_gid = 1001;

  struct passwd u2;
  static char u2_name[] = "user2";
  u2.pw_name = u2_name;
  u2.pw_uid = 1002;
  u2.pw_gid = 1003;  // Non-UPG primary GID

  struct passwd iter_users[] = {u1, u2};
  g_iter_users = iter_users;
  g_iter_users_count = 2;
  g_iter_idx = 0;

  EXPECT_EQ(_nss_cache_oslogin_setpwent(0), NSS_STATUS_SUCCESS);

  struct passwd pw;
  char pw_buf[1024];

  enum nss_status s =
      _nss_cache_oslogin_getpwent_r(&pw, pw_buf, sizeof(pw_buf), &errnop);
  EXPECT_EQ(s, NSS_STATUS_SUCCESS);
  EXPECT_STREQ(pw.pw_name, "user1");
  EXPECT_EQ(pw.pw_uid, 1001);

  // Interleave a UPG lookup and a non-UPG lookup (including when the binary
  // cache falls back to the legacy passwd file mid-iteration).
  struct group grp;
  char grp_buf[1024];
  mock_user = u1;
  mock_lookup_status = NSS_STATUS_SUCCESS;
  enum nss_status grp_s = _nss_cache_oslogin_getgrgid_r(
      1001, &grp, grp_buf, sizeof(grp_buf), &errnop);
  EXPECT_EQ(grp_s, NSS_STATUS_SUCCESS);
  EXPECT_STREQ(grp.gr_name, "user1");

  use_mock_binary_cache = false;
  grp_s = _nss_cache_oslogin_getgrgid_r(3000, &grp, grp_buf, sizeof(grp_buf),
                                        &errnop);
  EXPECT_EQ(grp_s, NSS_STATUS_NOTFOUND);
  use_mock_binary_cache = true;

  s = _nss_cache_oslogin_getpwent_r(&pw, pw_buf, sizeof(pw_buf), &errnop);
  EXPECT_EQ(s, NSS_STATUS_SUCCESS);
  EXPECT_STREQ(pw.pw_name, "user2");
  EXPECT_EQ(pw.pw_uid, 1002);

  s = _nss_cache_oslogin_getpwent_r(&pw, pw_buf, sizeof(pw_buf), &errnop);
  EXPECT_EQ(s, NSS_STATUS_NOTFOUND);

  EXPECT_EQ(_nss_cache_oslogin_endpwent(), NSS_STATUS_SUCCESS);
}

// Tests below exercise the legacy text cache fallback (use_mock_binary_cache =
// false).

TEST_F(NssCacheOsloginTest, LegacyGetPwUidSuccess) {
  use_mock_binary_cache = false;
  struct passwd result;
  enum nss_status status =
      _nss_cache_oslogin_getpwuid_r(1001, &result, buffer, BUFLEN, &errnop);
  ASSERT_EQ(status, NSS_STATUS_SUCCESS);
  ASSERT_STREQ(result.pw_name, "testuser");
  ASSERT_EQ(result.pw_uid, 1001);
  ASSERT_EQ(result.pw_gid, 1001);
}

TEST_F(NssCacheOsloginTest, LegacyGetPwUidNotFound) {
  use_mock_binary_cache = false;
  struct passwd result;
  enum nss_status status =
      _nss_cache_oslogin_getpwuid_r(9999, &result, buffer, BUFLEN, &errnop);
  ASSERT_EQ(status, NSS_STATUS_NOTFOUND);
}

TEST_F(NssCacheOsloginTest, LegacyGetGrGidForUPG) {
  use_mock_binary_cache = false;
  struct group result;
  enum nss_status status =
      _nss_cache_oslogin_getgrgid_r(1004, &result, buffer, BUFLEN, &errnop);
  ASSERT_EQ(status, NSS_STATUS_SUCCESS);
  ASSERT_STREQ(result.gr_name, "upguser");
  ASSERT_EQ(result.gr_gid, 1004);
}

TEST_F(NssCacheOsloginTest, LegacyGetGrGidNotFoundForNonUPG) {
  use_mock_binary_cache = false;
  struct group result;
  enum nss_status status =
      _nss_cache_oslogin_getgrgid_r(1003, &result, buffer, BUFLEN, &errnop);
  ASSERT_EQ(status, NSS_STATUS_NOTFOUND);
}

TEST_F(NssCacheOsloginTest, LegacyBufferTooSmall) {
  use_mock_binary_cache = false;
  struct passwd result;
  char small_buffer[5];
  enum nss_status status = _nss_cache_oslogin_getpwnam_r(
      "testuser", &result, small_buffer, sizeof(small_buffer), &errnop);
  ASSERT_EQ(status, NSS_STATUS_TRYAGAIN);
  ASSERT_EQ(errnop, ERANGE);
}

TEST_F(NssCacheOsloginTest, LegacyEnumerateAllUsers) {
  use_mock_binary_cache = false;
  struct passwd result;
  std::vector<std::string> users;

  _nss_cache_oslogin_setpwent(0);
  while (_nss_cache_oslogin_getpwent_r(&result, buffer, BUFLEN, &errnop) ==
         NSS_STATUS_SUCCESS) {
    users.push_back(result.pw_name);
  }
  _nss_cache_oslogin_endpwent();

  ASSERT_EQ(users.size(), 3u);
  ASSERT_EQ(users[0], "testuser");
  ASSERT_EQ(users[1], "another");
  ASSERT_EQ(users[2], "upguser");
}

TEST_F(NssCacheOsloginTest,
       LegacyInterleavedLookupDoesNotCorruptEnumerationState) {
  use_mock_binary_cache = false;
  struct passwd pwent_result;
  struct passwd pwnam_result;
  struct group grgid_result;
  char pwent_buffer[BUFLEN];
  char pwnam_buffer[BUFLEN];
  char grgid_buffer[BUFLEN];

  ASSERT_EQ(_nss_cache_oslogin_setpwent(0), NSS_STATUS_SUCCESS);

  ASSERT_EQ(_nss_cache_oslogin_getpwent_r(&pwent_result, pwent_buffer, BUFLEN,
                                          &errnop),
            NSS_STATUS_SUCCESS);
  ASSERT_STREQ(pwent_result.pw_name, "testuser");

  ASSERT_EQ(_nss_cache_oslogin_getpwnam_r("another", &pwnam_result,
                                          pwnam_buffer, BUFLEN, &errnop),
            NSS_STATUS_SUCCESS);
  ASSERT_STREQ(pwnam_result.pw_name, "another");

  ASSERT_EQ(_nss_cache_oslogin_getgrgid_r(3000, &grgid_result, grgid_buffer,
                                          BUFLEN, &errnop),
            NSS_STATUS_NOTFOUND);

  ASSERT_EQ(_nss_cache_oslogin_getpwent_r(&pwent_result, pwent_buffer, BUFLEN,
                                          &errnop),
            NSS_STATUS_SUCCESS);
  ASSERT_STREQ(pwent_result.pw_name, "another");

  _nss_cache_oslogin_endpwent();
}
