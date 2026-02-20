// Copyright 2026 Google Inc. All Rights Reserved.
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

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <ios>
#include <string>
#include <thread>
#include <vector>

#include <nss.h>
#include <pwd.h>

#include <gtest/gtest.h>

#include "oslogin_passwd_cache_reader.h"
#include "oslogin_passwd_cache_writer.h"

namespace {

class RoundTripTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::string temp_dir = ::testing::TempDir();
    filename_ = temp_dir + "/passwd.cache";
    std::string tmp_filename = temp_dir + "/passwd.cache.tmp";

    OsLoginPasswdCacheWriter writer;
    writer.AddUser("root", "x", 0, 0, "Root", "/", "/bin/bash");
    for (int i = 1000; i < 3000; ++i) {
      std::string user = "user" + std::to_string(i);
      std::string gecos = "User " + std::to_string(i);
      std::string home = "/home/" + user;
      writer.AddUser(user, "x", i, i, gecos, home, "/bin/bash");
    }
    std::ofstream out(tmp_filename, std::ios::binary);
    ASSERT_TRUE(writer.Commit(out));
    out.close();
    ASSERT_EQ(0, rename(tmp_filename.c_str(), filename_.c_str()));

    cache_ = open_passwd_cache(filename_.c_str());
    ASSERT_NE(cache_, nullptr);
  }

  void TearDown() override {
    if (cache_) {
      close_passwd_cache(cache_);
    }
  }

  void WriteUsers(int revision) {
    std::string temp_dir = ::testing::TempDir();
    std::string tmp_filename =
        temp_dir + "/passwd.cache.tmp." + std::to_string(revision);

    OsLoginPasswdCacheWriter writer;
    writer.AddUser("root", "x", 0, 0, "Root", "/", "/bin/bash");
    for (int i = 1000; i < 3000; ++i) {
      std::string user = "user" + std::to_string(i);
      std::string gecos =
          "User " + std::to_string(i) + " rev " + std::to_string(revision);
      std::string home = "/home/" + user;
      writer.AddUser(user, "x", i, i, gecos, home, "/bin/bash");
    }
    // Add a revision-specific user.
    writer.AddUser("user_rev" + std::to_string(revision), "x", 3000 + revision,
                   3000 + revision, "Rev user", "/", "/bin/bash");
    std::ofstream out(tmp_filename, std::ios::binary);
    ASSERT_TRUE(writer.Commit(out));
    out.close();
    ASSERT_EQ(0, rename(tmp_filename.c_str(), filename_.c_str()));
  }

  std::string filename_;
  PasswdCache* cache_ = nullptr;
};

TEST_F(RoundTripTest, WriteAndRead) {
  ASSERT_EQ(2001, get_passwd_cache_uid_count(cache_));
  ASSERT_EQ(2001, get_passwd_cache_name_count(cache_));

  // Test UID lookup
  struct passwd pwd;
  char buf[2048];
  int errnop;

  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_uid_r(cache_, 1500, &pwd, buf, sizeof(buf),
                                   &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("user1500", pwd.pw_name);
  EXPECT_EQ(1500, pwd.pw_uid);
  EXPECT_EQ(1500, pwd.pw_gid);
  EXPECT_STREQ("x", pwd.pw_passwd);
  EXPECT_STREQ("User 1500", pwd.pw_gecos);
  EXPECT_STREQ("/home/user1500", pwd.pw_dir);
  EXPECT_STREQ("/bin/bash", pwd.pw_shell);

  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_uid_r(cache_, 2500, &pwd, buf, sizeof(buf),
                                   &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("user2500", pwd.pw_name);
  EXPECT_EQ(2500, pwd.pw_uid);

  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_uid_r(cache_, 0, &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("root", pwd.pw_name);
  EXPECT_EQ(0, pwd.pw_uid);

  // Non-existent
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_uid_r(cache_, 9999, &pwd, buf, sizeof(buf),
                                   &errnop));
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_uid_r(cache_, 999, &pwd, buf, sizeof(buf),
                                   &errnop));
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_uid_r(cache_, 3000, &pwd, buf, sizeof(buf),
                                   &errnop));

  // Test name lookup
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(cache_, "user1500", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("user1500", pwd.pw_name);
  EXPECT_EQ(1500, pwd.pw_uid);

  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(cache_, "user2500", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("user2500", pwd.pw_name);
  EXPECT_EQ(2500, pwd.pw_uid);

  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(cache_, "root", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("root", pwd.pw_name);
  EXPECT_EQ(0, pwd.pw_uid);

  // Non-existent
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(cache_, "nouser", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(cache_, "a", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(cache_, "user", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(cache_, "user10000", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(cache_, "zzzz", &pwd, buf, sizeof(buf),
                                    &errnop));

  // Test buffer too small
  EXPECT_EQ(NSS_STATUS_TRYAGAIN,
            lookup_passwd_by_uid_r(cache_, 0, &pwd, buf, 10, &errnop));
  EXPECT_EQ(ERANGE, errnop);
}

TEST_F(RoundTripTest, ERangeNegotiation) {
  struct passwd pwd;
  char buf[24];  // Just enough for root user
  int errnop;

  // Buffer 23 should be too small for root user
  EXPECT_EQ(NSS_STATUS_TRYAGAIN,
            lookup_passwd_by_uid_r(cache_, 0, &pwd, buf, 23, &errnop));
  EXPECT_EQ(ERANGE, errnop);

  // Buffer 24 should be just enough for root user
  EXPECT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_uid_r(cache_, 0, &pwd, buf, 24, &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("root", pwd.pw_name);
  EXPECT_STREQ("x", pwd.pw_passwd);
  EXPECT_STREQ("Root", pwd.pw_gecos);
  EXPECT_STREQ("/", pwd.pw_dir);
  EXPECT_STREQ("/bin/bash", pwd.pw_shell);

  // Lookup by name too
  EXPECT_EQ(NSS_STATUS_TRYAGAIN,
            lookup_passwd_by_name_r(cache_, "root", &pwd, buf, 23, &errnop));
  EXPECT_EQ(ERANGE, errnop);
  EXPECT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(cache_, "root", &pwd, buf, 24, &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("root", pwd.pw_name);
}

TEST_F(RoundTripTest, NamePrefixLookup) {
  std::string temp_dir = ::testing::TempDir();
  std::string filename = temp_dir + "/prefix.cache";
  std::string tmp_filename = temp_dir + "/prefix.cache.tmp";

  OsLoginPasswdCacheWriter writer;
  writer.AddUser("a", "x", 1, 1, "", "/", "");
  writer.AddUser("b", "x", 2, 2, "", "/", "");
  writer.AddUser("bar", "x", 3, 3, "", "/", "");
  writer.AddUser("bart", "x", 4, 4, "", "/", "");
  writer.AddUser("baz", "x", 5, 5, "", "/", "");
  writer.AddUser("foo", "x", 6, 6, "", "/", "");
  std::ofstream out(tmp_filename, std::ios::binary);
  ASSERT_TRUE(writer.Commit(out));
  out.close();
  ASSERT_EQ(0, rename(tmp_filename.c_str(), filename.c_str()));

  PasswdCache* cache = open_passwd_cache(filename.c_str());
  ASSERT_NE(cache, nullptr);

  struct passwd pwd;
  char buf[1024];
  int errnop;

  // Test successful lookups
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(
                cache, "a", &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(1, pwd.pw_uid);
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(
                cache, "b", &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(2, pwd.pw_uid);
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(
                cache, "bar", &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(3, pwd.pw_uid);
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(
                cache, "bart", &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(4, pwd.pw_uid);
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(
                cache, "baz", &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(5, pwd.pw_uid);
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(
                cache, "foo", &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(6, pwd.pw_uid);

  // Test non-existent lookups, including prefixes and extensions
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(
                cache, "ba", &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(
                cache, "bartender", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(
                cache, "fo", &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(
                cache, "foobar", &pwd, buf, sizeof(buf),
                                    &errnop));

  close_passwd_cache(cache);
}

TEST_F(RoundTripTest, Iteration) {
  PasswdCacheIter iter;
  struct passwd pwd;
  char buf[2048];
  int errnop;
  int count = 0;

  // Test ERange first
  passwd_cache_iter_begin(cache_, &iter);
  char small_buf[10];
  EXPECT_EQ(NSS_STATUS_TRYAGAIN,
            passwd_cache_iter_next_r(cache_, &iter, &pwd, small_buf,
                                     sizeof(small_buf), &errnop));
  EXPECT_EQ(ERANGE, errnop);

  // Retry with large buffer - should return first entry "root" because
  // iterator should not advance on TRYAGAIN.
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            passwd_cache_iter_next_r(
                cache_, &iter, &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("root", pwd.pw_name);
  count++;

  // Next users 1000-2999
  for (int i = 1000; i < 3000; ++i) {
    ASSERT_EQ(NSS_STATUS_SUCCESS,
              passwd_cache_iter_next_r(
                  cache_, &iter, &pwd, buf, sizeof(buf), &errnop));
    EXPECT_EQ(0, errnop);
    EXPECT_EQ(i, pwd.pw_uid);
    std::string expected_name = "user" + std::to_string(i);
    EXPECT_STREQ(expected_name.c_str(), pwd.pw_name);
    count++;
  }

  // Should be no more entries
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            passwd_cache_iter_next_r(
                cache_, &iter, &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(2001, count);

  // Calling again should still return NOTFOUND
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            passwd_cache_iter_next_r(
                cache_, &iter, &pwd, buf, sizeof(buf), &errnop));

  // Test reset with begin()
  passwd_cache_iter_begin(cache_, &iter);
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            passwd_cache_iter_next_r(
                cache_, &iter, &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("root", pwd.pw_name);
}

TEST_F(RoundTripTest, ConcurrentLookups) {
  std::vector<std::thread> threads;
  for (int i = 0; i < 16; ++i) {
    threads.emplace_back([this, i]() {
      struct passwd pwd;
      char buf[2048];
      int errnop;
      const int kStride = 31;
      const int kUsers = 2000;
      for (int j = 0; j < 1000; ++j) {
        // Lookup users known to exist
        uid_t uid_to_find = 1000 + (i + j * kStride) % kUsers;
        ASSERT_EQ(NSS_STATUS_SUCCESS,
                  lookup_passwd_by_uid_r(
                      cache_, uid_to_find, &pwd, buf,
                                           sizeof(buf), &errnop));
        EXPECT_EQ(0, errnop);
        EXPECT_EQ(uid_to_find, pwd.pw_uid);
        std::string expected_name = "user" + std::to_string(uid_to_find);
        EXPECT_STREQ(expected_name.c_str(), pwd.pw_name);

        const std::string name_to_find =
            "user" + std::to_string(1000 + (i + 100 + j * kStride) % kUsers);
        ASSERT_EQ(NSS_STATUS_SUCCESS,
                  lookup_passwd_by_name_r(cache_, name_to_find.c_str(), &pwd,
                                            buf, sizeof(buf), &errnop));
        EXPECT_EQ(0, errnop);
        EXPECT_STREQ(name_to_find.c_str(), pwd.pw_name);

        // Lookup non-existent
        EXPECT_EQ(NSS_STATUS_NOTFOUND,
                  lookup_passwd_by_uid_r(cache_,
                      3000 + (i + j * kStride) % kUsers,
                      &pwd, buf, sizeof(buf), &errnop));
        EXPECT_EQ(
            NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(
                cache_,
                ("user" + std::to_string(
                    3000 + (i + 100 + j * kStride) % kUsers))
                      .c_str(),
                &pwd, buf, sizeof(buf), &errnop));
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }
}

TEST_F(RoundTripTest, ConcurrentReadWithAtomicUpdate) {
  std::atomic<bool> done{false};
  std::vector<std::thread> threads;
  for (int i = 0; i < 16; ++i) {
    threads.emplace_back([this, &done, i]() {
      struct passwd pwd;
      char buf[2048];
      int errnop;
      const int kStride = 31;
      const int kUsers = 2000;
      int j = 0;
      while (!done) {
        uid_t uid_to_find = 1000 + (i + j * kStride) % kUsers;
        auto status = lookup_passwd_by_uid_r(cache_, uid_to_find, &pwd, buf,
                                             sizeof(buf), &errnop);
        // We must either succeed or fail with NOTFOUND.
        // TRYAGAIN is only OK if buffer is too small (ERANGE), not if
        // data is corrupt (EINVAL).
        ASSERT_TRUE(status == NSS_STATUS_SUCCESS ||
                    status == NSS_STATUS_NOTFOUND ||
                    (status == NSS_STATUS_TRYAGAIN && errnop == ERANGE));
        if (status == NSS_STATUS_SUCCESS) {
          EXPECT_EQ(uid_to_find, pwd.pw_uid);
          std::string expected_name = "user" + std::to_string(uid_to_find);
          EXPECT_STREQ(expected_name.c_str(), pwd.pw_name);
        }

        // Also check for revision users that are being added by the writer.
        // They should not be found in our stale mmap view, and looking them
        // up should be safe (not crash or return corrupt data).
        int rev_num = j % 5;
        uid_t rev_uid = 3000 + rev_num;
        status = lookup_passwd_by_uid_r(cache_, rev_uid, &pwd, buf, sizeof(buf),
                                        &errnop);
        ASSERT_TRUE(status == NSS_STATUS_NOTFOUND ||
                    (status == NSS_STATUS_TRYAGAIN && errnop == ERANGE));

        std::string rev_name = "user_rev" + std::to_string(rev_num);
        status = lookup_passwd_by_name_r(cache_, rev_name.c_str(), &pwd, buf,
                                         sizeof(buf), &errnop);
        ASSERT_TRUE(status == NSS_STATUS_NOTFOUND ||
                    (status == NSS_STATUS_TRYAGAIN && errnop == ERANGE));
        j++;
      }
    });
  }

  // While readers are running, update the cache file multiple times.
  for (int rev = 0; rev < 5; ++rev) {
    WriteUsers(rev);
  }

  done = true;
  for (auto& t : threads) {
    t.join();
  }
}

TEST_F(RoundTripTest, UnsortedInput) {
  std::string temp_dir = ::testing::TempDir();
  std::string filename = temp_dir + "/unsorted.cache";
  std::string tmp_filename = temp_dir + "/unsorted.cache.tmp";

  OsLoginPasswdCacheWriter writer;
  writer.AddUser(
      "user2", "x", 2000, 2000, "User 2", "/home/user2", "/bin/bash");
  writer.AddUser(
      "user1", "x", 1000, 1000, "User 1", "/home/user1", "/bin/bash");
  writer.AddUser(
      "user3", "x", 3000, 3000, "User 3", "/home/user3", "/bin/bash");
  std::ofstream out(tmp_filename, std::ios::binary);
  ASSERT_TRUE(writer.Commit(out));
  out.close();
  ASSERT_EQ(0, rename(tmp_filename.c_str(), filename.c_str()));

  PasswdCache* cache = open_passwd_cache(filename.c_str());
  ASSERT_NE(cache, nullptr);

  ASSERT_EQ(3, get_passwd_cache_uid_count(cache));
  ASSERT_EQ(3, get_passwd_cache_name_count(cache));

  struct passwd pwd;
  char buf[1024];
  int errnop;

  // Verify UID lookups
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_uid_r(cache, 1000, &pwd, buf, sizeof(buf),
                                   &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("user1", pwd.pw_name);

  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_uid_r(cache, 2000, &pwd, buf, sizeof(buf),
                                   &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("user2", pwd.pw_name);

  ASSERT_EQ(3, get_passwd_cache_uid_count(cache));
  ASSERT_EQ(3, get_passwd_cache_name_count(cache));

  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_uid_r(cache, 3000, &pwd, buf, sizeof(buf),
                                   &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_STREQ("user3", pwd.pw_name);

  // Verify name lookups
  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(cache, "user1", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_EQ(1000, pwd.pw_uid);

  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(cache, "user2", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_EQ(2000, pwd.pw_uid);

  ASSERT_EQ(NSS_STATUS_SUCCESS,
            lookup_passwd_by_name_r(cache, "user3", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(0, errnop);
  EXPECT_EQ(3000, pwd.pw_uid);

  close_passwd_cache(cache);
}

TEST_F(RoundTripTest, EmptyCache) {
  std::string temp_dir = ::testing::TempDir();
  std::string filename = temp_dir + "/empty.cache";
  std::string tmp_filename = temp_dir + "/empty.cache.tmp";

  OsLoginPasswdCacheWriter writer;
  std::ofstream out(tmp_filename, std::ios::binary);
  ASSERT_TRUE(writer.Commit(out));
  out.close();
  ASSERT_EQ(0, rename(tmp_filename.c_str(), filename.c_str()));

  PasswdCache* cache = open_passwd_cache(filename.c_str());
  ASSERT_NE(cache, nullptr);

  struct passwd pwd;
  char buf[1024];
  int errnop;

  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_uid_r(cache, 1000, &pwd, buf, sizeof(buf),
                                   &errnop));
  EXPECT_EQ(NSS_STATUS_NOTFOUND,
            lookup_passwd_by_name_r(cache, "user1", &pwd, buf, sizeof(buf),
                                    &errnop));

  close_passwd_cache(cache);
}

}  // namespace
