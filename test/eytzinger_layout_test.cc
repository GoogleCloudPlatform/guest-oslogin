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

#include "eytzinger_layout.h"

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "oslogin_index_structs.h"

namespace {

// Helper to create UID input vector
std::vector<OsLoginIndexUID> CreateUidVector(const std::vector<uid_t>& uids) {
  std::vector<OsLoginIndexUID> vec;
  vec.reserve(uids.size());
  for (uid_t uid : uids) {
    vec.push_back({.text_offset = 0, .uid = uid});
  }
  return vec;
}

// Helper to create Name input vector
std::vector<OsLoginIndexName> CreateNameVector(
    const std::vector<std::string>& names) {
  std::vector<OsLoginIndexName> vec;
  vec.reserve(names.size());
  for (const std::string& name : names) {
    vec.push_back({.left_child_offset = 0,
                   .right_child_offset = 0,
                   .text_offset = 0,
                   .name_len = 0,
                   .name = name,
                   .self_offset = 0});
  }
  return vec;
}

TEST(EytzingerLayoutTest, EmptyVector) {
  std::vector<OsLoginIndexUID> uid_vector;
  auto result = to_eytzinger_layout(uid_vector);
  EXPECT_TRUE(result.empty());

  std::vector<OsLoginIndexName> name_vector;
  auto result_name = to_eytzinger_layout(name_vector);
  EXPECT_TRUE(result_name.empty());
}

TEST(EytzingerLayoutTest, SingleElement) {
  auto result = to_eytzinger_layout(CreateUidVector({10}));
  ASSERT_EQ(1, result.size());
  EXPECT_EQ(10, result[0].uid);

  auto result_name = to_eytzinger_layout(CreateNameVector({"a"}));
  ASSERT_EQ(1, result_name.size());
  EXPECT_EQ("a", result_name[0].name);
}

TEST(EytzingerLayoutTest, ThreeElements) {
  auto result = to_eytzinger_layout(CreateUidVector({10, 20, 30}));
  ASSERT_EQ(3, result.size());
  EXPECT_EQ(20, result[0].uid);
  EXPECT_EQ(10, result[1].uid);
  EXPECT_EQ(30, result[2].uid);

  auto result_name = to_eytzinger_layout(CreateNameVector({"a", "b", "c"}));
  ASSERT_EQ(3, result_name.size());
  EXPECT_EQ("b", result_name[0].name);
  EXPECT_EQ("a", result_name[1].name);
  EXPECT_EQ("c", result_name[2].name);
}

TEST(EytzingerLayoutTest, SevenElements) {
  auto result =
      to_eytzinger_layout(CreateUidVector({10, 20, 30, 40, 50, 60, 70}));
  ASSERT_EQ(7, result.size());
  EXPECT_EQ(40, result[0].uid);
  EXPECT_EQ(20, result[1].uid);
  EXPECT_EQ(60, result[2].uid);
  EXPECT_EQ(10, result[3].uid);
  EXPECT_EQ(30, result[4].uid);
  EXPECT_EQ(50, result[5].uid);
  EXPECT_EQ(70, result[6].uid);

  auto result_name = to_eytzinger_layout(
      CreateNameVector({"a", "b", "c", "d", "e", "f", "g"}));
  ASSERT_EQ(7, result_name.size());
  EXPECT_EQ("d", result_name[0].name);
  EXPECT_EQ("b", result_name[1].name);
  EXPECT_EQ("f", result_name[2].name);
  EXPECT_EQ("a", result_name[3].name);
  EXPECT_EQ("c", result_name[4].name);
  EXPECT_EQ("e", result_name[5].name);
  EXPECT_EQ("g", result_name[6].name);
}

TEST(EytzingerLayoutTest, TwoElements) {
  auto result = to_eytzinger_layout(CreateUidVector({10, 20}));
  ASSERT_EQ(2, result.size());
  EXPECT_EQ(20, result[0].uid);
  EXPECT_EQ(10, result[1].uid);

  auto result_name = to_eytzinger_layout(CreateNameVector({"a", "b"}));
  ASSERT_EQ(2, result_name.size());
  EXPECT_EQ("b", result_name[0].name);
  EXPECT_EQ("a", result_name[1].name);
}

TEST(EytzingerLayoutTest, FourElements) {
  auto result = to_eytzinger_layout(CreateUidVector({10, 20, 30, 40}));
  ASSERT_EQ(4, result.size());
  EXPECT_EQ(30, result[0].uid);
  EXPECT_EQ(20, result[1].uid);
  EXPECT_EQ(40, result[2].uid);
  EXPECT_EQ(10, result[3].uid);

  auto result_name =
      to_eytzinger_layout(CreateNameVector({"a", "b", "c", "d"}));
  ASSERT_EQ(4, result_name.size());
  EXPECT_EQ("c", result_name[0].name);
  EXPECT_EQ("b", result_name[1].name);
  EXPECT_EQ("d", result_name[2].name);
  EXPECT_EQ("a", result_name[3].name);
}

TEST(EytzingerLayoutTest, FiveElements) {
  auto result = to_eytzinger_layout(CreateUidVector({10, 20, 30, 40, 50}));
  ASSERT_EQ(5, result.size());
  EXPECT_EQ(40, result[0].uid);
  EXPECT_EQ(20, result[1].uid);
  EXPECT_EQ(50, result[2].uid);
  EXPECT_EQ(10, result[3].uid);
  EXPECT_EQ(30, result[4].uid);

  auto result_name =
      to_eytzinger_layout(CreateNameVector({"a", "b", "c", "d", "e"}));
  ASSERT_EQ(5, result_name.size());
  EXPECT_EQ("d", result_name[0].name);
  EXPECT_EQ("b", result_name[1].name);
  EXPECT_EQ("e", result_name[2].name);
  EXPECT_EQ("a", result_name[3].name);
  EXPECT_EQ("c", result_name[4].name);
}

TEST(EytzingerLayoutTest, SixElements) {
  auto result = to_eytzinger_layout(CreateUidVector({10, 20, 30, 40, 50, 60}));
  ASSERT_EQ(6, result.size());
  EXPECT_EQ(40, result[0].uid);
  EXPECT_EQ(20, result[1].uid);
  EXPECT_EQ(60, result[2].uid);
  EXPECT_EQ(10, result[3].uid);
  EXPECT_EQ(30, result[4].uid);
  EXPECT_EQ(50, result[5].uid);

  auto result_name =
      to_eytzinger_layout(CreateNameVector({"a", "b", "c", "d", "e", "f"}));
  ASSERT_EQ(6, result_name.size());
  EXPECT_EQ("d", result_name[0].name);
  EXPECT_EQ("b", result_name[1].name);
  EXPECT_EQ("f", result_name[2].name);
  EXPECT_EQ("a", result_name[3].name);
  EXPECT_EQ("c", result_name[4].name);
  EXPECT_EQ("e", result_name[5].name);
}

}  // namespace
