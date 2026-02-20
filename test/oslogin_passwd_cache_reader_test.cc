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

#include "oslogin_passwd_cache_reader.h"

#include <cerrno>
#include <string>

#include <gtest/gtest.h>
#include <nss.h>
#include <pwd.h>

namespace {

TEST(OsLoginPasswdCacheReaderTest, MissingFile) {
  std::string temp_dir = ::testing::TempDir();
  std::string missing_filename = temp_dir + "/no_such_file.cache";

  PasswdCache* cache = open_passwd_cache(missing_filename.c_str());
  EXPECT_EQ(cache, nullptr);

  struct passwd pwd;
  char buf[1024];
  int errnop;

  EXPECT_EQ(NSS_STATUS_UNAVAIL,
            lookup_passwd_by_uid_r(
                nullptr, 1000, &pwd, buf, sizeof(buf), &errnop));
  EXPECT_EQ(ENOENT, errnop);

  EXPECT_EQ(NSS_STATUS_UNAVAIL,
            lookup_passwd_by_name_r(nullptr, "user1000", &pwd, buf, sizeof(buf),
                                    &errnop));
  EXPECT_EQ(ENOENT, errnop);
}

}  // namespace
