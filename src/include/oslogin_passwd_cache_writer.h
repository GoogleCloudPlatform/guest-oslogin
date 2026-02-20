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

#ifndef OSLOGIN_OSLOGIN_PASSWD_CACHE_WRITER_H
#define OSLOGIN_OSLOGIN_PASSWD_CACHE_WRITER_H

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "include/oslogin_index_structs.h"

class OsLoginPasswdCacheWriter {
 public:
  // Constructor: Opens the temporary file for writing.
  // The final filename is provided for the Commit() step,
  // but the temporary file is used for all actual writing.
  OsLoginPasswdCacheWriter();

  // Destructor: Closes the file.
  // Warning: If Commit() was not called, the file will be incomplete/invalid.
  ~OsLoginPasswdCacheWriter();

  // Adds a user entry to the cache.
  // This writes the text line immediately and buffers the index entries in RAM.
  void AddUser(const std::string& name,
               const std::string& passwd,
               uid_t uid,
               gid_t gid,
               const std::string& gecos,
               const std::string& dir,
               const std::string& shell);

  // Finalizes the cache file.
  // 1. Sorts the in-memory indices.
  // 2. Writes a header with pointers to the index and text sections.
  // 3. Writes the UID Index section.
  // 4. Writes the Name Index section.
  // 5. Writes the text lines.
  // Returns true on success.
  // The caller is responsible for opening and closing the ofstream.
  bool Commit(std::ofstream& out);

 private:
  // In-memory buffer for the text lines (`passwd`-like format)
  std::ostringstream text_buffer_;

  // In-memory buffers for the indices
  // We collect these as we add users, then sort them at Commit time.
  std::vector<OsLoginIndexUID> uid_index_;
  std::vector<OsLoginIndexName> name_index_;
};

#endif  // OSLOGIN_OSLOGIN_PASSWD_CACHE_WRITER_H
