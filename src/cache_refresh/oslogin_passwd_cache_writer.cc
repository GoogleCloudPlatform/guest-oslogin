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

#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <endian.h>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <vector>

#include "include/eytzinger_layout.h"
#include "include/oslogin_index_structs.h"
#include "include/oslogin_passwd_cache_writer.h"

constexpr size_t kIndexNameRecordBaseSize =
    sizeof(uint64_t) * 3 + sizeof(uint16_t);

namespace {
struct passwd_cache_header {
  uint64_t uid_index_offset;
  uint64_t uid_index_len;  // number of entries
  uint64_t name_index_offset;
  uint64_t name_index_len;  // number of entries
  uint64_t text_offset;
  uint64_t text_len;  // in bytes
};
constexpr size_t kHeaderSize = 6 * sizeof(uint64_t);

void write_le64(std::ofstream& out, uint64_t data) {
    uint64_t le_data = htole64(data);
    out.write(reinterpret_cast<const char*>(&le_data), sizeof(le_data));
}

void write_le32(std::ofstream& out, uint32_t data) {
    uint32_t le_data = htole32(data);
    out.write(reinterpret_cast<const char*>(&le_data), sizeof(le_data));
}

void write_le16(std::ofstream& out, uint16_t data) {
    uint16_t le_data = htole16(data);
    out.write(reinterpret_cast<const char*>(&le_data), sizeof(le_data));
}

}  // namespace

OsLoginPasswdCacheWriter::OsLoginPasswdCacheWriter() = default;

OsLoginPasswdCacheWriter::~OsLoginPasswdCacheWriter() = default;

void OsLoginPasswdCacheWriter::AddUser(const std::string& name,
                                       const std::string& passwd,
                                       uid_t uid,
                                       gid_t gid,
                                       const std::string& gecos,
                                       const std::string& dir,
                                       const std::string& shell) {
  // 1. Format the text line
  std::ostringstream line;
  line << name << ":" << passwd << ":" << uid << ":" << gid << ":"
       << gecos << ":" << dir << ":" << shell << "\n";
  std::string line_str = line.str();

  // 2. Calculate the "Relative Offset"
  uint64_t relative_offset = (uint64_t)text_buffer_.tellp();

  // 3. Buffer the text
  text_buffer_ << line_str;

  // 4. Create Index Entries (with RELATIVE offsets for now)
  OsLoginIndexUID uid_entry {};
  uid_entry.text_offset = relative_offset;  // Temporary!
  uid_entry.uid = uid;
  uid_index_.push_back(uid_entry);

  OsLoginIndexName name_entry {};
  name_entry.text_offset = relative_offset;  // Temporary!
  name_entry.name_len = name.size();
  name_entry.name = name;
  name_index_.push_back(name_entry);
}

bool OsLoginPasswdCacheWriter::Commit(std::ofstream& out) {
  // 1. Sort the in-memory indices.
  std::sort(uid_index_.begin(), uid_index_.end());
  std::sort(name_index_.begin(), name_index_.end());

  // Convert to Eytzinger layout.
  uid_index_ = to_eytzinger_layout(uid_index_);
  name_index_ = to_eytzinger_layout(name_index_);

  // For each name index entry, the size is kIndexNameRecordBaseSize + name_len.
  // This means that the offset of each entry is equal to the sum of the sizes
  // of all preceding entries. We can calculate the correct value for each entry
  // by iterating through the sorted array and accumulating the size.
  uint64_t name_index_offset = 0;
  for (auto& entry : name_index_) {
    entry.self_offset = name_index_offset;
    name_index_offset += kIndexNameRecordBaseSize + entry.name_len;
  }

  for (size_t i = 0; i < name_index_.size(); ++i) {
    size_t left_child_index = 2 * (i + 1) - 1;
    size_t right_child_index = 2 * (i + 1);
    if (left_child_index < name_index_.size()) {
      name_index_[i].left_child_offset =
          name_index_[left_child_index].self_offset;
    }
    if (right_child_index < name_index_.size()) {
      name_index_[i].right_child_offset =
          name_index_[right_child_index].self_offset;
    }
  }

  // Now we know the correct offsets for everything. We can write to the file.
  uint64_t uid_section_size =
      uid_index_.size() * (sizeof(uint64_t) + sizeof(uint32_t));
  uint64_t name_section_size = name_index_offset;  // Accumulated above

  passwd_cache_header header;
  header.uid_index_len = uid_index_.size();
  header.name_index_len = name_index_.size();
  header.uid_index_offset = kHeaderSize;
  header.name_index_offset = header.uid_index_offset + uid_section_size;
  header.text_offset = header.name_index_offset + name_section_size;
  std::string text = text_buffer_.str();
  header.text_len = text.length();

  for (auto& entry : uid_index_) {
    entry.text_offset += header.text_offset;
  }
  for (auto& entry : name_index_) {
    entry.text_offset += header.text_offset;
    if (entry.left_child_offset != 0) {
      entry.left_child_offset += header.name_index_offset;
    }
    if (entry.right_child_offset != 0) {
      entry.right_child_offset += header.name_index_offset;
    }
  }

  if (!out) {
    return false;
  }

  // Write header fields individually in little-endian to avoid padding issues
  // and ensure endian compatibility for C99 interop.
  write_le64(out, header.uid_index_offset);
  write_le64(out, header.uid_index_len);
  write_le64(out, header.name_index_offset);
  write_le64(out, header.name_index_len);
  write_le64(out, header.text_offset);
  write_le64(out, header.text_len);

  for (const auto& entry : uid_index_) {
    write_le64(out, entry.text_offset);
    write_le32(out, entry.uid);
  }

  for (const auto& entry : name_index_) {
    write_le64(out, entry.text_offset);
    write_le64(out, entry.left_child_offset);
    write_le64(out, entry.right_child_offset);
    write_le16(out, entry.name_len);
    out.write(entry.name.c_str(), entry.name_len);
  }

  out.write(text.c_str(), text.length());

  if (out.fail()) {
    return false;
  }
  return true;
}
