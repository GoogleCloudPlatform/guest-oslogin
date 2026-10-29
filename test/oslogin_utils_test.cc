// Copyright 2019 Google Inc. All Rights Reserved.
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
#include "oslogin_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <ios>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "compat.h"

using std::string;
using std::vector;

namespace oslogin_utils {

// Test that the buffer can successfully append multiple strings.
TEST(BufferManagerTest, TestAppendString) {
  size_t buflen = 20;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);

  char* first_string;
  char* second_string;
  int test_errno = 0;
  oslogin_utils::BufferManager buffer_manager(buffer, buflen);
  buffer_manager.AppendString("test1", &first_string, &test_errno);
  buffer_manager.AppendString("test2", &second_string, &test_errno);
  ASSERT_EQ(test_errno, 0);
  ASSERT_STREQ(first_string, "test1");
  ASSERT_STREQ(second_string, "test2");
  ASSERT_STREQ(buffer, "test1");
  ASSERT_STREQ((buffer + 6), "test2");
}

// Test that attempting to append a string larger than the buffer can handle
// fails with ERANGE.
TEST(BufferManagerTest, TestAppendStringTooLarge) {
  size_t buflen = 1;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);

  char* first_string;
  int test_errno = 0;
  oslogin_utils::BufferManager buffer_manager(buffer, buflen);
  ASSERT_FALSE(
      buffer_manager.AppendString("test1", &first_string, &test_errno));
  ASSERT_EQ(test_errno, ERANGE);
}

// Test successfully loading and retrieving an array of JSON posix accounts.
TEST(NssCacheTest, TestLoadJsonArray) {
  NssCache nss_cache(2);
  string test_user1 =
      "{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":1337,\"gid\":1337,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}";
  string test_user2 =
      "{\"name\":\"bar@example.com\","
      "\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"bar\",\"uid\":1338,\"gid\":1338,"
      "\"homeDirectory\":\"/home/bar\",\"shell\":\"/bin/bash\"}]}";
  string response = "{\"loginProfiles\": [" + test_user1 + ", " + test_user2 +
                    "], \"nextPageToken\": \"token\"}";

  ASSERT_TRUE(nss_cache.LoadJsonUsersToCache(response));

  size_t buflen = 500;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;

  // Verify that the first user was stored.
  ASSERT_TRUE(nss_cache.HasNextEntry());
  ASSERT_TRUE(nss_cache.GetNextPasswd(&buf, &result, &test_errno));
  ASSERT_EQ(test_errno, 0);
  ASSERT_EQ(result.pw_uid, 1337);
  ASSERT_EQ(result.pw_gid, 1337);
  ASSERT_STREQ(result.pw_name, "foo");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
  ASSERT_STREQ(result.pw_dir, "/home/foo");

  // Verify that the second user was stored.
  ASSERT_TRUE(nss_cache.HasNextEntry());
  ASSERT_TRUE(nss_cache.GetNextPasswd(&buf, &result, &test_errno));
  ASSERT_EQ(test_errno, 0);
  ASSERT_EQ(result.pw_uid, 1338);
  ASSERT_EQ(result.pw_gid, 1338);
  ASSERT_STREQ(result.pw_name, "bar");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
  ASSERT_STREQ(result.pw_dir, "/home/bar");

  // Verify that there are no more users stored.
  ASSERT_FALSE(nss_cache.HasNextEntry());
  ASSERT_FALSE(nss_cache.GetNextPasswd(&buf, &result, &test_errno));
  ASSERT_EQ(test_errno, ENOENT);
}

// The cache refresher skips entries that fail with EINVAL and keeps going, so
// an entry with a delimiter in a field must not affect the entries after it.
TEST(NssCacheTest, SkipsPasswdEntryWithDelimiterInField) {
  NssCache nss_cache(2);
  string bad_user =
      "{\"name\":\"bad@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"a:b\",\"uid\":1337,\"gid\":1337,"
      "\"homeDirectory\":\"/home/a\",\"shell\":\"/bin/bash\"}]}";
  string good_user =
      "{\"name\":\"bar@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"bar\",\"uid\":1338,\"gid\":1338,"
      "\"homeDirectory\":\"/home/bar\",\"shell\":\"/bin/bash\"}]}";
  string response = "{\"loginProfiles\": [" + bad_user + ", " + good_user +
                    "], \"nextPageToken\": \"token\"}";
  ASSERT_TRUE(nss_cache.LoadJsonUsersToCache(response));

  size_t buflen = 500;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;

  ASSERT_FALSE(nss_cache.GetNextPasswd(&buf, &result, &test_errno));
  ASSERT_EQ(test_errno, EINVAL);

  test_errno = 0;
  ASSERT_TRUE(nss_cache.GetNextPasswd(&buf, &result, &test_errno));
  ASSERT_EQ(test_errno, 0);
  ASSERT_STREQ(result.pw_name, "bar");
}


// Test successfully loading and retrieving a partial array.
TEST(NssCacheTest, TestLoadJsonPartialArray) {
  NssCache nss_cache(2);
  string test_user1 =
      "{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":1337,\"gid\":1337,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}";
  string response =
      "{\"loginProfiles\": [" + test_user1 + "], \"nextPageToken\": \"token\"}";

  ASSERT_TRUE(nss_cache.LoadJsonUsersToCache(response));

  size_t buflen = 500;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;

  // Verify that the first user was stored.
  ASSERT_TRUE(nss_cache.HasNextEntry());
  ASSERT_TRUE(nss_cache.GetNextPasswd(&buf, &result, &test_errno));
  ASSERT_EQ(test_errno, 0);
  ASSERT_EQ(result.pw_uid, 1337);
  ASSERT_EQ(result.pw_gid, 1337);
  ASSERT_STREQ(result.pw_name, "foo");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
  ASSERT_STREQ(result.pw_dir, "/home/foo");

  ASSERT_EQ(nss_cache.GetPageToken(), "token");

  // Verify that there are no more users stored.
  ASSERT_FALSE(nss_cache.HasNextEntry());
  ASSERT_FALSE(nss_cache.GetNextPasswd(&buf, &result, &test_errno));
  ASSERT_EQ(test_errno, ENOENT);
}

// Test successfully loading and retrieving the final response.
TEST(NssCacheTest, TestLoadJsonFinalResponse) {
  NssCache nss_cache(2);
  string response = "{\"nextPageToken\": \"0\"}";

  ASSERT_TRUE(nss_cache.LoadJsonUsersToCache(response));
  ASSERT_EQ(nss_cache.GetPageToken(), "");

  size_t buflen = 500;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;

  // Verify that there are no more users stored.
  ASSERT_FALSE(nss_cache.HasNextEntry());
  ASSERT_TRUE(nss_cache.OnLastPage());
  ASSERT_FALSE(nss_cache.GetNextPasswd(&buf, &result, &test_errno));
  ASSERT_EQ(test_errno, ENOENT);
}

// Tests that resetting, and checking HasNextEntry does not crash.
TEST(NssCacheTest, ResetNullPtrTest) {
  NssCache nss_cache(2);
  nss_cache.Reset();
  ASSERT_FALSE(nss_cache.HasNextEntry());
}

// Test parsing a valid JSON response from the metadata server.
TEST(ParseJsonPasswdTest, ParseJsonToPasswdSucceeds) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":1337,\"gid\":1338,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_TRUE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(result.pw_uid, 1337);
  ASSERT_EQ(result.pw_gid, 1338);
  ASSERT_STREQ(result.pw_name, "foo");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
  ASSERT_STREQ(result.pw_dir, "/home/foo");
}

// Test parsing a valid JSON response from the metadata server with uid > 2^31.
TEST(ParseJsonPasswdTest, ParseJsonToPasswdSucceedsWithHighUid) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":4294967295,\"gid\":"
      "4294967295,\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_TRUE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(result.pw_uid, 4294967295);
  ASSERT_EQ(result.pw_gid, 4294967295);
  ASSERT_STREQ(result.pw_name, "foo");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
  ASSERT_STREQ(result.pw_dir, "/home/foo");
}

TEST(ParseJsonPasswdTest, ParseJsonToPasswdSucceedsWithStringUid) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":\"1337\",\"gid\":"
      "\"1338\",\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_TRUE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(result.pw_uid, 1337);
  ASSERT_EQ(result.pw_gid, 1338);
  ASSERT_STREQ(result.pw_name, "foo");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
  ASSERT_STREQ(result.pw_dir, "/home/foo");
}

TEST(ParseJsonPasswdTest, ParseJsonToPasswdNoLoginProfilesSucceeds) {
  string test_user =
      "{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":1337,\"gid\":1337,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_TRUE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(result.pw_uid, 1337);
  ASSERT_EQ(result.pw_gid, 1337);
  ASSERT_STREQ(result.pw_name, "foo");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
  ASSERT_STREQ(result.pw_dir, "/home/foo");
}

TEST(ParseJsonPasswdTest, ParseJsonToPasswdFailsWithLowGid) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":2001,\"gid\":6,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_FALSE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(test_errno, EINVAL);
}

TEST(ParseJsonPasswdTest, ParseJsonToPasswdFailsWithLowGidString) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":\"2001\",\"gid\":\"6\","
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_FALSE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(test_errno, EINVAL);
}

TEST(ParseJsonPasswdTest, ParseJsonToPasswdFailsWithGid999) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":2001,\"gid\":999,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_FALSE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(test_errno, EINVAL);
}

TEST(ParseJsonPasswdTest, ParseJsonToPasswdSucceedsWithGid1000) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":1000,\"gid\":1000,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_TRUE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(result.pw_uid, 1000);
  ASSERT_EQ(result.pw_gid, 1000);
  ASSERT_STREQ(result.pw_name, "foo");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
  ASSERT_STREQ(result.pw_dir, "/home/foo");
}

TEST(ParseJsonPasswdTest, ParseJsonToPasswdSucceedsWithGidZeroDefaultsToUid) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":2001,\"gid\":0,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_TRUE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(result.pw_uid, 2001);
  ASSERT_EQ(result.pw_gid, 2001);
  ASSERT_STREQ(result.pw_name, "foo");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
  ASSERT_STREQ(result.pw_dir, "/home/foo");
}

TEST(ParseJsonPasswdTest,
     ParseJsonToPasswdSucceedsWithOmittedGidDefaultsToUid) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":2001,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_TRUE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(result.pw_uid, 2001);
  ASSERT_EQ(result.pw_gid, 2001);
  ASSERT_STREQ(result.pw_name, "foo");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
  ASSERT_STREQ(result.pw_dir, "/home/foo");
}

// Test parsing a JSON response without enough space in the buffer.
TEST(ParseJsonPasswdTest, ParseJsonToPasswdFailsWithERANGE) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":1337,\"gid\":1337,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 1;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_FALSE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(test_errno, ERANGE);
}

// Test parsing malformed JSON responses.
TEST(ParseJsonPasswdTest, ParseJsonToPasswdFailsWithEINVAL) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\": \"bad_stuff\""
      ",\"gid\":1337,\"homeDirectory\":\"/home/foo\","
      "\"shell\":\"/bin/bash\"}]}]}";
  string test_user2 =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\": 1337,"
      "\"gid\":\"bad_stuff\",\"homeDirectory\":\"/home/foo\","
      "\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_FALSE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(test_errno, EINVAL);
  // Reset errno.
  test_errno = 0;
  ASSERT_TRUE(ParseJsonToPasswd(test_user2, &result, &buf, &test_errno));
  ASSERT_EQ(test_errno, 0);
  ASSERT_EQ(result.pw_uid, 1337);
  ASSERT_EQ(result.pw_gid, 1337);
}

// A colon or newline in a passwd field would corrupt the NSS cache record.
TEST(ParseJsonPasswdTest, ParseJsonToPasswdFailsWithDelimiterInField) {
  string colon_in_username =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"a:b\",\"uid\":1337,\"gid\":1338,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";
  string newline_in_home =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":1337,\"gid\":1338,"
      "\"homeDirectory\":\"/home/foo\\nroot\",\"shell\":\"/bin/bash\"}]}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_FALSE(
      ParseJsonToPasswd(colon_in_username, &result, &buf, &test_errno));
  ASSERT_EQ(test_errno, EINVAL);

  test_errno = 0;
  ASSERT_FALSE(ParseJsonToPasswd(newline_in_home, &result, &buf, &test_errno));
  ASSERT_EQ(test_errno, EINVAL);
}


// Test parsing a partially filled response. Validate should fill empty fields
// with default values.
TEST(ParseJsonPasswdTest, ValidatePartialJsonResponse) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":1337,\"gid\":1337}]"
      "}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_TRUE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(result.pw_uid, 1337);
  ASSERT_EQ(result.pw_gid, 1337);
  ASSERT_STREQ(result.pw_name, "foo");
  ASSERT_STREQ(result.pw_shell, DEFAULT_SHELL);
  ASSERT_STREQ(result.pw_dir, "/home/foo");
}

// Test parsing an invalid response. Validate should cause the parse to fail if
// there is no uid.
TEST(ParseJsonPasswdTest, ValidateInvalidJsonResponse) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"gid\":1337}]"
      "}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;
  ASSERT_FALSE(ParseJsonToPasswd(test_user, &result, &buf, &test_errno));
  ASSERT_EQ(test_errno, EINVAL);
}


TEST(CurlClient, RetryLogic) {
  ASSERT_FALSE(ShouldRetry(200));
  ASSERT_FALSE(ShouldRetry(404));
  ASSERT_FALSE(ShouldRetry(400));
  ASSERT_TRUE(ShouldRetry(429));
}

// Exercises the curl_easy_perform failure path. The assertion alone can't see
// a leak; run under --config=asan so LeakSanitizer can. Requests run on a
// separate thread (its stack is gone after join, so stale stack slots can't
// hide a leaked pointer) and repeat so one masked block can't hide the leak.
TEST(CurlClient, HttpGetFailsCleanlyWhenUnreachable) {
  std::thread worker([] {
    for (int i = 0; i < 50; ++i) {
      string response;
      long http_code = 0;
      EXPECT_FALSE(HttpGet("http://127.0.0.1:1/", &response, &http_code));
    }
  });
  worker.join();
}

TEST(ParseJsonEmailTest, SuccessfullyParsesEmail) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"gid\":1337}]"
      "}]}";

  string email;
  ASSERT_TRUE(ParseJsonToEmail(test_user, &email));
  ASSERT_EQ(email, "foo@example.com");
}

TEST(ParseJsonEmailTest, FailsParseEmail) {
  string email;
  ASSERT_FALSE(ParseJsonToEmail("random_junk", &email));
  ASSERT_EQ(email, "");
}

TEST(ParseJsonSshKeyTest, ParseJsonToSshKeysSucceeds) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"sshPublicKeys\":"
      "{\"fingerprint\": {\"key\": \"test_key\"}}}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  std::vector<string> result = ParseJsonToSshKeys(test_user);
  ASSERT_EQ(result.size(), 1);
  ASSERT_EQ(result[0], "test_key");
}

TEST(ParseJsonSshKeyTest, ParseJsonToSshKeysMultipleKeys) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"sshPublicKeys\":"
      "{\"fingerprint\": {\"key\": \"test_key\"}, \"fingerprint2\": {\"key\": "
      "\"test_key2\"}}}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  std::vector<string> result = ParseJsonToSshKeys(test_user);
  ASSERT_EQ(result.size(), 2);
  ASSERT_EQ(result[0], "test_key");
  ASSERT_EQ(result[1], "test_key2");
}

TEST(ParseJsonSshKeyTest, ParseJsonToSshKeysFiltersExpiredKeys) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"sshPublicKeys\":"
      "{\"fingerprint\": {\"key\": \"test_key\"}, \"fingerprint2\": {\"key\": "
      "\"test_key2\", \"expirationTimeUsec\": 0}}}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  std::vector<string> result = ParseJsonToSshKeys(test_user);
  ASSERT_EQ(result.size(), 1);
  ASSERT_EQ(result[0], "test_key");
}

TEST(ParseJsonSshKeyTest, ParseJsonToSshKeysFiltersMalformedExpiration) {
  string test_user =
      "{\"loginProfiles\":[{\"name\":\"foo@example.com\",\"sshPublicKeys\":"
      "{\"fingerprint\": {\"key\": \"test_key\"}, \"fingerprint2\": {\"key\": "
      "\"test_key2\", \"expirationTimeUsec\": \"bad_stuff\"}}}]}";

  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen * sizeof(char));
  ASSERT_STRNE(buffer, NULL);
  BufferManager buf(buffer, buflen);
  std::vector<string> result = ParseJsonToSshKeys(test_user);
  ASSERT_EQ(result.size(), 1);
  ASSERT_EQ(result[0], "test_key");
}

TEST(ParseJsonAuthorizeSuccess, SuccessfullyAuthorized) {
  string response = "{\"success\": true}";
  ASSERT_TRUE(ParseJsonToSuccess(response));
}

TEST(ValidateUserNameTest, ValidateValidUserNames) {
  string cases[] = {"user",  "_",   ".",    ".abc_",
                    "_abc-", "ABC", "A_.-", "ausernamethirtytwocharacterslong"};
  for (auto test_user : cases) {
    ASSERT_TRUE(ValidateUserName(test_user));
  }
}

TEST(ValidateUserNameTest, ValidateInvalidUserNames) {
  string cases[] = {
      "",
      "!#$%^",
      "-abc",
      "#abc",
      "^abc",
      "abc*xyz",
      "abc xyz",
      "xyz*",
      "xyz$",
      "usernamethirtythreecharacterslong",
      "../../etc/shadow",
  };
  for (auto test_user : cases) {
    ASSERT_FALSE(ValidateUserName(test_user));
  }
}

TEST(ParseJsonKeyTest, TestKey) {
  string test_json = "{\"some_key\":\"some_value\"}";
  string value;
  ASSERT_TRUE(ParseJsonToKey(test_json, "some_key", &value));
  ASSERT_EQ(value, "some_value");
}

TEST(ParseJsonKeyTest, TestMissingKey) {
  string test_json = "{\"some_key\":\"some_value\"}";
  string value;
  ASSERT_FALSE(ParseJsonToKey(test_json, "some_other_key", &value));
  ASSERT_EQ(value, "");
}

TEST(ParseJsonChallengesTest, TestChallenges) {
  string challenges_json =
      "{\"status\":\"CHALLENGE_REQUIRED\",\"sessionId\":"
      "\"testSessionId\",\"challenges\":[{\"challengeId\":1,\"challengeType\":"
      "\"TOTP\",\"status\":\"READY\"}, {\"challengeId\":2,\"challengeType\":"
      "\"AUTHZEN\",\"status\":\"PROPOSED\"}]}";
  vector<Challenge> challenges;
  ASSERT_TRUE(ParseJsonToChallenges(challenges_json, &challenges));
  ASSERT_EQ(challenges.size(), 2);
  ASSERT_EQ(challenges[0].id, 1);
  ASSERT_EQ(challenges[0].type, "TOTP");
}

TEST(ParseJsonChallengesTest, TestMalformedChallenges) {
  string challenges_json =
      "{\"status\":\"CHALLENGE_REQUIRED\",\"sessionId\":"
      "\"testSessionId\",\"challenges\":[{\"challengeId\":1,\"challengeType\":"
      "\"TOTP\",\"status\":\"READY\"}, {\"challengeId\":2,\"challengeType\":"
      "\"AUTHZEN\"}]}";
  vector<Challenge> challenges;
  ASSERT_FALSE(ParseJsonToChallenges(challenges_json, &challenges));
  ASSERT_EQ(challenges.size(), 1);
}

TEST(ParseJsonChallengesTest, TestEmptyChallenges) {
  string challenges_json =
      "{\"status\":\"CHALLENGE_REQUIRED\",\"sessionId\":\"testSessionId\","
      "\"challenges\":[]}";
  vector<Challenge> challenges;
  ASSERT_TRUE(ParseJsonToChallenges(challenges_json, &challenges));
  ASSERT_TRUE(challenges.empty());
}


TEST(UrlEncodeTest, EncodesSpecialCharacters) {
  EXPECT_EQ(UrlEncode("abc"), "abc");
  EXPECT_EQ(UrlEncode("a b"), "a%20b");
  EXPECT_EQ(UrlEncode("a&b"), "a%26b");
  EXPECT_EQ(UrlEncode("a/b"), "a%2Fb");
}

TEST(AuthorizeUserTest, RejectsInvalidUserNames) {
  struct AuthOptions opts = {};
  string user_response;

  // Empty username.
  EXPECT_FALSE(AuthorizeUser("", opts, &user_response));

  // Traversal and path separator injection attempts.
  EXPECT_FALSE(AuthorizeUser("../victim", opts, &user_response));
  EXPECT_FALSE(AuthorizeUser("users/foo", opts, &user_response));
  EXPECT_FALSE(AuthorizeUser("/etc/shadow", opts, &user_response));

  // Disallowed punctuation, spaces, and command injection characters.
  EXPECT_FALSE(AuthorizeUser("user with spaces", opts, &user_response));
  EXPECT_FALSE(AuthorizeUser("attacker;id", opts, &user_response));
  EXPECT_FALSE(AuthorizeUser("user$name", opts, &user_response));
  EXPECT_FALSE(AuthorizeUser("attacker|sh", opts, &user_response));
  EXPECT_FALSE(AuthorizeUser("user`whoami`", opts, &user_response));
  EXPECT_FALSE(AuthorizeUser("user\nadmin", opts, &user_response));

  // Username starting with invalid characters.
  EXPECT_FALSE(AuthorizeUser("-admin", opts, &user_response));
  EXPECT_FALSE(AuthorizeUser("!user", opts, &user_response));

  // Length limits: >32 characters.
  string too_long_user(33, 'a');
  EXPECT_FALSE(AuthorizeUser(too_long_user.c_str(), opts, &user_response));
}

TEST(AuthorizeUserTest, HandlesMdsFailureGracefully) {
  struct AuthOptions opts = {};
  opts.admin_policy_required = false;
  opts.security_key = false;
  opts.fingerprint = nullptr;
  opts.fp_len = 0;
  string user_response;

  // With a valid username format, AuthorizeUser proceeds to MDS check.
  // In an environment without metadata server, it must safely fail and return false without crashing.
  EXPECT_FALSE(AuthorizeUser("testuser", opts, &user_response));
  EXPECT_FALSE(AuthorizeUser("testuser", opts, &user_response, /*cloud_run=*/true));
}

TEST(AuthorizeUserTest, RejectsWhenAdminPolicyRequiredAndMdsUnavailable) {
  struct AuthOptions opts = {};
  opts.admin_policy_required = true;
  opts.security_key = false;
  opts.fingerprint = nullptr;
  opts.fp_len = 0;
  string user_response;

  EXPECT_FALSE(AuthorizeUser("testadmin", opts, &user_response));
}

TEST(AuthorizeUserJourneyTest, ParseUserResponseToEmail) {
  string valid_response =
      "{\"loginProfiles\":[{\"name\":\"user@example.com\"}]}";
  string email;
  EXPECT_TRUE(ParseJsonToEmail(valid_response, &email));
  EXPECT_EQ(email, "user@example.com");

  // Missing name field in loginProfiles.
  string missing_email = "{\"loginProfiles\":[{}]}";
  email.clear();
  EXPECT_FALSE(ParseJsonToEmail(missing_email, &email));

  // Missing loginProfiles.
  string missing_profiles = "{}";
  email.clear();
  EXPECT_FALSE(ParseJsonToEmail(missing_profiles, &email));

  // Malformed JSON.
  string malformed = "not-a-json";
  email.clear();
  EXPECT_FALSE(ParseJsonToEmail(malformed, &email));
}

TEST(AuthorizeUserJourneyTest, ParsePolicyResponseSuccessAndFailure) {
  // Successful policy authorization.
  string success_json = "{\"success\": true}";
  EXPECT_TRUE(ParseJsonToSuccess(success_json));

  // Denied policy authorization.
  string denied_json = "{\"success\": false}";
  EXPECT_FALSE(ParseJsonToSuccess(denied_json));

  // Missing success field.
  string empty_json = "{}";
  EXPECT_FALSE(ParseJsonToSuccess(empty_json));

  // Malformed JSON.
  string malformed = "invalid json";
  EXPECT_FALSE(ParseJsonToSuccess(malformed));
}

TEST(FileNameTest, ExtractsBasenameCorrectly) {
  EXPECT_STREQ(FileName("/var/google-users.d/testuser"), "testuser");
  EXPECT_STREQ(FileName("/var/google-sudoers.d/testadmin"), "testadmin");
  EXPECT_STREQ(FileName("path/to/testuser"), "testuser");
  EXPECT_STREQ(FileName("/testuser"), "testuser");
  EXPECT_STREQ(FileName("testuser"), "testuser");
  EXPECT_STREQ(FileName(""), "");
}

TEST(SysLogTest, CloseSysLogResetsLogger) {
  SetupSysLog("oslogin_utils_test", "app%");
  SysLogErr("n=%d", 1);
  CloseSysLog();
  // Second call is a safe no-op.
  CloseSysLog();
  // SetupSysLog with NULL ident is a no-op.
  SetupSysLog(NULL, "app");
  SysLogErr("ignored");
}

TEST(NssCacheTest, LoadJsonUsersRejectsMalformedInput) {
  struct TestCase {
    int page_size;
    string json;
    bool expected_result;
  };
  std::vector<TestCase> test_cases = {
      {2, "not json", false},
      {2, "{\"loginProfiles\":[]}", false},
      {2, "{\"nextPageToken\":\"t\"}", false},
      {2, "{\"nextPageToken\":\"t\",\"loginProfiles\":{}}", false},
      {1, "{\"nextPageToken\":\"t\",\"loginProfiles\":[]}", false},
      {1, "{\"nextPageToken\":\"t\",\"loginProfiles\":[{},{}]}", false},
  };
  for (const auto& tc : test_cases) {
    NssCache nss_cache(tc.page_size);
    EXPECT_EQ(nss_cache.LoadJsonUsersToCache(tc.json), tc.expected_result);
  }
}

TEST(NssCacheTest, GetpwentHelperServesPreloadedPage) {
  NssCache nss_cache(2);
  string test_user1 =
      "{\"name\":\"foo@example.com\",\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"foo\",\"uid\":1337,\"gid\":1337,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}";
  string test_user2 =
      "{\"name\":\"bar@example.com\","
      "\"posixAccounts\":["
      "{\"primary\":true,\"username\":\"bar\",\"uid\":1338,\"gid\":1338,"
      "\"homeDirectory\":\"/home/bar\",\"shell\":\"/bin/bash\"}]}";
  string response = "{\"loginProfiles\": [" + test_user1 + ", " + test_user2 +
                    "], \"nextPageToken\": \"token\"}";

  ASSERT_TRUE(nss_cache.LoadJsonUsersToCache(response));

  size_t buflen = 500;
  char* buffer = (char*)malloc(buflen);
  ASSERT_NE(buffer, nullptr);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;

  EXPECT_TRUE(nss_cache.NssGetpwentHelper(&buf, &result, &test_errno));
  EXPECT_EQ(test_errno, 0);
  EXPECT_STREQ(result.pw_name, "foo");

  EXPECT_TRUE(nss_cache.NssGetpwentHelper(&buf, &result, &test_errno));
  EXPECT_EQ(test_errno, 0);
  EXPECT_STREQ(result.pw_name, "bar");

  free(buffer);
}

TEST(NssCacheTest, GetpwentHelperOnLastPageReturnsFalse) {
  NssCache nss_cache(2);
  ASSERT_TRUE(nss_cache.LoadJsonUsersToCache("{\"nextPageToken\":\"0\"}"));
  EXPECT_TRUE(nss_cache.OnLastPage());

  size_t buflen = 500;
  char* buffer = (char*)malloc(buflen);
  ASSERT_NE(buffer, nullptr);
  BufferManager buf(buffer, buflen);
  struct passwd result;
  int test_errno = 0;

  EXPECT_FALSE(nss_cache.NssGetpwentHelper(&buf, &result, &test_errno));

  free(buffer);
}

TEST(CurlClient, OnCurlWriteWritesToStream) {
  std::ostringstream os;
  EXPECT_EQ(OnCurlWrite((void*)"abc", 1, 3, &os), 3);
  EXPECT_EQ(os.str(), "abc");
}

TEST(CurlClient, OnCurlWriteRejectsNullAndBadStream) {
  EXPECT_EQ(OnCurlWrite((void*)"abc", 1, 3, NULL), 0);
  std::ostringstream os;
  os.setstate(std::ios::badbit);
  EXPECT_EQ(OnCurlWrite((void*)"abc", 1, 3, &os), 0);
}

TEST(CurlClient, HttpGetRejectsNullOutputs) {
  long http_code = 0;
  string response;
  EXPECT_FALSE(HttpGet("http://127.0.0.1:1/", NULL, &http_code));
  EXPECT_FALSE(HttpGet("http://127.0.0.1:1/", &response, NULL));
}

TEST(CurlClient, HttpPostFailsCleanlyWhenUnreachable) {
  string response;
  long http_code = 0;
  EXPECT_FALSE(
      HttpPost("http://127.0.0.1:1/", "{\"a\":1}", &response, &http_code));
}

TEST(ValidatePasswdTest, RejectsEmptyName) {
  size_t buflen = 500;
  char* buffer = (char*)malloc(buflen);
  ASSERT_NE(buffer, nullptr);
  BufferManager buf(buffer, buflen);
  struct passwd pwd;
  pwd.pw_uid = 1337;
  pwd.pw_gid = 1337;
  pwd.pw_name = (char*)"";
  pwd.pw_dir = (char*)"";
  pwd.pw_shell = (char*)"";
  pwd.pw_passwd = (char*)"";
  int test_errno = 0;
  EXPECT_FALSE(ValidatePasswd(&pwd, &buf, &test_errno));
  EXPECT_EQ(test_errno, EINVAL);
  free(buffer);
}

TEST(ValidatePasswdTest, FailsWithERANGEWhenDefaultsDoNotFit) {
  size_t len1 = strlen("/home/foo") + 1;
  size_t len2 = len1 + strlen(DEFAULT_SHELL) + 1;
  size_t len3 = len2 + strlen(DEFAULT_PASSWD) + 1;

  struct TestCase {
    size_t buflen;
    bool expected_result;
    int expected_errno;
  };
  std::vector<TestCase> test_cases = {
      // No room for the default home directory.
      {0, false, ERANGE},
      // Home directory fits; the default shell does not.
      {len1, false, ERANGE},
      // Home directory and shell fit; the default passwd does not.
      {len2, false, ERANGE},
      // Home directory, shell and passwd fit; the empty gecos does not.
      {len3, false, ERANGE},
  };

  for (const auto& tc : test_cases) {
    char* buffer = (char*)malloc(tc.buflen);
    BufferManager buf(buffer, tc.buflen);
    struct passwd pwd;
    pwd.pw_uid = 1337;
    pwd.pw_gid = 1337;
    pwd.pw_name = (char*)"foo";
    pwd.pw_dir = (char*)"";
    pwd.pw_shell = (char*)"";
    pwd.pw_passwd = (char*)"";
    int test_errno = 0;
    EXPECT_EQ(ValidatePasswd(&pwd, &buf, &test_errno), tc.expected_result);
    EXPECT_EQ(test_errno, tc.expected_errno);
    free(buffer);
  }
}

TEST(ParseJsonSshKeyTest, ReturnsEmptyOnMalformedProfile) {
  EXPECT_TRUE(ParseJsonToSshKeys("junk").empty());
  EXPECT_TRUE(ParseJsonToSshKeys("{}").empty());
  EXPECT_TRUE(ParseJsonToSshKeys("{\"loginProfiles\":{}}").empty());
  EXPECT_TRUE(ParseJsonToSshKeys("{\"loginProfiles\":[{}]}").empty());
  EXPECT_TRUE(ParseJsonToSshKeys("{\"loginProfiles\":[{\"sshPublicKeys\":[]}]}")
                  .empty());
}

TEST(ParseJsonSshKeyTest, SkipsNonObjectEntriesAndNonStringKeys) {
  string json =
      "{\"loginProfiles\":[{\"sshPublicKeys\":{"
      "\"fp1\":\"str\","
      "\"fp2\":{\"key\":123},"
      "\"fp3\":{\"key\":\"ok\",\"expirationTimeUsec\":true}}}]}";
  std::vector<string> keys = ParseJsonToSshKeys(json);
  ASSERT_EQ(keys.size(), 1);
  EXPECT_EQ(keys[0], "ok");
}

TEST(ParseJsonSshKeySkTest, ParsesSecurityKeys) {
  struct TestCase {
    string json;
    std::vector<string> expected_keys;
  };
  std::vector<TestCase> test_cases = {
      {"{\"loginProfiles\":[{\"securityKeys\":["
       "{\"publicKey\":\"sk1\"},"
       "{\"publicKey\":\"sk2\"}]}]}",
       {"sk1", "sk2"}},
      {"{\"loginProfiles\":[{\"securityKeys\":["
       "{\"publicKey\":\"sk1\"},\"str\"]}]}",
       {"sk1"}},
      {"{\"loginProfiles\":[{\"securityKeys\":["
       "{\"publicKey\":\"sk1\"},{}]}]}",
       {"sk1"}},
  };
  for (const auto& tc : test_cases) {
    EXPECT_EQ(ParseJsonToSshKeysSk(tc.json), tc.expected_keys);
  }
}

TEST(ParseJsonSshKeySkTest, ReturnsEmptyOnMalformedProfile) {
  std::vector<string> invalid_jsons = {
      "junk",
      "{}",
      "{\"loginProfiles\":5}",
      "{\"loginProfiles\":[{}]}",
      "{\"loginProfiles\":[{\"securityKeys\":{}}]}",
  };
  for (const auto& json : invalid_jsons) {
    EXPECT_TRUE(ParseJsonToSshKeysSk(json).empty());
  }
}

TEST(ParseJsonPasswdTest, RejectsMalformedInput) {
  size_t buflen = 500;
  char* buffer = (char*)malloc(buflen);
  ASSERT_NE(buffer, nullptr);
  BufferManager buf(buffer, buflen);
  struct passwd pwd;

  struct TestCase {
    string json;
    bool expected_result;
    int expected_errno;
  };

  std::vector<TestCase> test_cases = {
      {"junk", false, EINVAL},
      {"{\"loginProfiles\":{}}", false, EINVAL},
      {"{\"loginProfiles\":[{}]}", false, EINVAL},
      {"{\"loginProfiles\":[{\"posixAccounts\":{}}]}", false, EINVAL},
      {"{\"loginProfiles\":[{\"posixAccounts\":[1]}]}", false, EINVAL},
      // uid: true (not int or string)
      {"{\"loginProfiles\":[{\"posixAccounts\":[{\"username\":\"foo\",\"uid\":"
       "true,"
       "\"gid\":1337,\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/"
       "bash\"}]}]}",
       false, EINVAL},
      // gid: true (not int or string)
      {"{\"loginProfiles\":[{\"posixAccounts\":[{\"username\":\"foo\",\"uid\":"
       "1337,"
       "\"gid\":true,\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/"
       "bash\"}]}]}",
       false, EINVAL},
      // username: 1 (not string)
      {"{\"loginProfiles\":[{\"posixAccounts\":[{\"username\":1,\"uid\":1337,"
       "\"gid\":1337,\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/"
       "bash\"}]}]}",
       false, EINVAL},
      // homeDirectory: 1 (not string)
      {"{\"loginProfiles\":[{\"posixAccounts\":[{\"username\":\"foo\",\"uid\":"
       "1337,"
       "\"gid\":1337,\"homeDirectory\":1,\"shell\":\"/bin/bash\"}]}]}",
       false, EINVAL},
      // shell: 1 (not string)
      {"{\"loginProfiles\":[{\"posixAccounts\":[{\"username\":\"foo\",\"uid\":"
       "1337,"
       "\"gid\":1337,\"homeDirectory\":\"/home/foo\",\"shell\":1}]}]}",
       false, EINVAL},
  };

  for (const auto& tc : test_cases) {
    int test_errno = 0;
    EXPECT_EQ(ParseJsonToPasswd(tc.json, &pwd, &buf, &test_errno),
              tc.expected_result);
    EXPECT_EQ(test_errno, tc.expected_errno);
  }

  free(buffer);
}

TEST(ParseJsonPasswdTest, FailsWithERANGEOnHomeAndShell) {
  string json =
      "{\"loginProfiles\":[{\"posixAccounts\":[{"
      "\"username\":\"foo\",\"uid\":1337,\"gid\":1337,"
      "\"homeDirectory\":\"/home/foo\",\"shell\":\"/bin/bash\"}]}]}";
  struct passwd pwd;
  int test_errno = 0;

  // Four bytes hold "foo" but not the home directory.
  char* buf4 = (char*)malloc(4);
  BufferManager bm4(buf4, 4);
  EXPECT_FALSE(ParseJsonToPasswd(json, &pwd, &bm4, &test_errno));
  EXPECT_EQ(test_errno, ERANGE);
  free(buf4);

  // Fourteen bytes hold "foo" and "/home/foo" but not the shell.
  char* buf14 = (char*)malloc(14);
  BufferManager bm14(buf14, 14);
  test_errno = 0;
  EXPECT_FALSE(ParseJsonToPasswd(json, &pwd, &bm14, &test_errno));
  EXPECT_EQ(test_errno, ERANGE);
  free(buf14);
}

TEST(AddUsersToGroupTest, EmptyListIsNoop) {
  struct group grp;
  size_t buflen = 100;
  char* buffer = (char*)malloc(buflen);
  ASSERT_NE(buffer, nullptr);
  BufferManager buf(buffer, buflen);
  int test_errno = 0;
  EXPECT_TRUE(AddUsersToGroup({}, &grp, &buf, &test_errno));
  free(buffer);
}

TEST(AddUsersToGroupTest, PopulatesNullTerminatedMemberArray) {
  struct group grp;
  size_t buflen = 200;
  char* buffer = (char*)malloc(buflen);
  ASSERT_NE(buffer, nullptr);
  BufferManager buf(buffer, buflen);
  int test_errno = 0;
  std::vector<string> users = {"a", "b"};
  EXPECT_TRUE(AddUsersToGroup(users, &grp, &buf, &test_errno));
  ASSERT_NE(grp.gr_mem, nullptr);
  EXPECT_STREQ(grp.gr_mem[0], "a");
  EXPECT_STREQ(grp.gr_mem[1], "b");
  EXPECT_EQ(grp.gr_mem[2], nullptr);
  free(buffer);
}

TEST(AddUsersToGroupTest, FailsWithERANGE) {
  struct group grp;
  int test_errno = 0;

  // An empty buffer cannot hold the gr_mem pointer array.
  char buf0[1];
  BufferManager bm0(buf0, 0);
  EXPECT_FALSE(AddUsersToGroup({"alice"}, &grp, &bm0, &test_errno));
  EXPECT_EQ(test_errno, ERANGE);

  // Room for the two-pointer gr_mem array, but not for the member name.
  size_t ptrs_size = 2 * sizeof(char*);
  char* bufp = (char*)malloc(ptrs_size);
  BufferManager bmp(bufp, ptrs_size);
  test_errno = 0;
  EXPECT_FALSE(AddUsersToGroup({"alice"}, &grp, &bmp, &test_errno));
  EXPECT_EQ(test_errno, ERANGE);
  EXPECT_EQ(grp.gr_mem, nullptr);
  free(bufp);
}

TEST(ParseJsonEmailTest, RejectsNonArrayLoginProfiles) {
  string email;
  EXPECT_FALSE(ParseJsonToEmail("{\"loginProfiles\":{}}", &email));
}

TEST(ParseJsonKeyTest, RejectsInvalidJsonAndNullValue) {
  string response;
  EXPECT_FALSE(ParseJsonToKey("junk", "k", &response));
  EXPECT_FALSE(ParseJsonToKey("{\"k\":null}", "k", &response));
}

TEST(ParseJsonChallengesTest, RejectsInvalidJsonAndMissingFields) {
  std::vector<Challenge> challenges;
  EXPECT_FALSE(ParseJsonToChallenges("junk", &challenges));
  EXPECT_FALSE(ParseJsonToChallenges("{}", &challenges));
  EXPECT_FALSE(ParseJsonToChallenges(
      "{\"challenges\":[{\"challengeType\":\"TOTP\",\"status\":\"READY\"}]}",
      &challenges));
  EXPECT_FALSE(ParseJsonToChallenges(
      "{\"challenges\":[{\"challengeId\":1,\"status\":\"READY\"}]}",
      &challenges));
}

}  // namespace oslogin_utils
