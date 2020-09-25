// Copyright 2020 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Requires libgtest-dev and gtest compiled and installed.
#include <errno.h>
#include <gtest/gtest.h>
#include "../src/nss/new_nss_oslogin.c" // yes, the c file.
#include <nss.h>
#include <stdio.h>
#include <stdlib.h>

TEST(ParserTest, TestParsepasswd) {
  int res;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = parsepasswd((char *)"username:x:601004:89939:User Name:/home/username:/bin/bash",
                   &result, buf, buflen);

  ASSERT_EQ(res, 0);
  ASSERT_EQ(result.pw_uid, 601004);
  ASSERT_EQ(result.pw_gid, 89939);
  ASSERT_STREQ(result.pw_name, "username");
  ASSERT_STREQ(result.pw_passwd, "x");
  ASSERT_STREQ(result.pw_gecos , "User Name");
  ASSERT_STREQ(result.pw_dir, "/home/username");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
}

TEST(ParserTest, TestParsepasswdErange) {
  int res;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32;
  buf = (char *)malloc(buflen);

  res = parsepasswd((char *)"username:x:601004:89939:User Name:/home/username:/bin/bash",
                   &result, buf, buflen);

  ASSERT_EQ(res, ERANGE);
}

TEST(ParserTest, TestParsepasswdEnoent) {
  int res;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = parsepasswd((char *)"username:x:601004:89939:User Name:/home/username",
                   &result, buf, buflen);

  ASSERT_EQ(res, ENOENT);
}

TEST(ParserTest, TestParsegroup) {
  int res;
  ssize_t buflen;
  struct group result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = parsegroup((char *)"group-name:x:1000:member1,member2,member3,member4",
                   &result, buf, buflen);

  ASSERT_EQ(res, 0);
  ASSERT_EQ(result.gr_gid, 1000);
  ASSERT_STREQ(result.gr_name, "group-name");
  ASSERT_STREQ(result.gr_passwd, "x");
  ASSERT_STREQ(result.gr_mem[0], "member1");
  ASSERT_STREQ(result.gr_mem[1], "member2");
  ASSERT_STREQ(result.gr_mem[2], "member3");
  ASSERT_STREQ(result.gr_mem[3], "member4");
}

TEST(ParserTest, TestParsegroupErange) {
  int res;
  ssize_t buflen;
  struct group result;
  char *buf;

  buflen = 32;
  buf = (char *)malloc(buflen);

  res = parsegroup((char *)"group-name:x:1000:member1,member2,member3,member4",
                   &result, buf, buflen);

  ASSERT_EQ(res, ERANGE);
}

TEST(ParserTest, TestParsegroupEnoent) {
  int res;
  ssize_t buflen;
  struct group result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = parsegroup((char *)"group-name:x", &result, buf, buflen);

  ASSERT_EQ(res, ENOENT);
}

TEST(IntegTest, TestGetpwnam) {
  int res, errnop;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = _nss_oslogin_getpwnam_r("testuser", &result, buf, buflen, &errnop);
  ASSERT_EQ(res, NSS_STATUS_SUCCESS);
}

TEST(IntegTest, TestGetpwuid) {
  int res, errnop;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = _nss_oslogin_getpwuid_r(1000, &result, buf, buflen, &errnop);
  ASSERT_EQ(res, NSS_STATUS_SUCCESS);
}

TEST(IntegTest, TestGetgrnam) {
  int res, errnop;
  ssize_t buflen;
  struct group result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = _nss_oslogin_getgrnam_r("testuser", &result, buf, buflen, &errnop);
  ASSERT_EQ(res, NSS_STATUS_SUCCESS);
  ASSERT_STREQ(result.gr_name, "testuser");
  ASSERT_EQ(result.gr_gid, 1000);
}

TEST(IntegTest, TestGetgrgid) {
  nss_status res;
  int errnop;
  ssize_t buflen;
  struct group result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = _nss_oslogin_getgrgid_r(1000, &result, buf, buflen, &errnop);
  ASSERT_EQ(res, NSS_STATUS_SUCCESS);
  ASSERT_STREQ(result.gr_name, "testuser");
  ASSERT_EQ(result.gr_gid, 1000);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
