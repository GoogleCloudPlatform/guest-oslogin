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

#ifndef OSLOGIN_OSLOGIN_INDEX_STRUCTS_H
#define OSLOGIN_OSLOGIN_INDEX_STRUCTS_H

#include <sys/types.h>

#include <cstdint>
#include <string>

struct OsLoginIndexUID {
  uint64_t text_offset;
  uid_t uid;

  bool operator<(const OsLoginIndexUID& other) const {
    return uid < other.uid;
  }
};

struct OsLoginIndexName {
  uint64_t left_child_offset;
  uint64_t right_child_offset;
  uint64_t text_offset;
  uint16_t name_len;
  std::string name;

  // Only used in-memory and not written to disk. Used to store the relative
  // offset of each entry in the name index during construction.
  uint64_t self_offset;

  bool operator<(const OsLoginIndexName& other) const {
    return name < other.name;
  }
};

#endif  // OSLOGIN_OSLOGIN_INDEX_STRUCTS_H
