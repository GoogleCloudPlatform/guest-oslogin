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

#ifndef OSLOGIN_PASSWD_CACHE_READER_H
#define OSLOGIN_PASSWD_CACHE_READER_H

#include <nss.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// We need this for the C++ tests.
#ifdef __cplusplus
extern "C" {
#endif

typedef struct PasswdCache PasswdCache;

PasswdCache* open_passwd_cache(const char* filename);
void close_passwd_cache(PasswdCache* cache);

// NSS-style lookup functions.
// Return NSS_STATUS_SUCCESS if found, NSS_STATUS_NOTFOUND if not found,
// NSS_STATUS_TRYAGAIN if buffer too small (errnop=ERANGE) or parse error
// (errnop=EINVAL).
enum nss_status lookup_passwd_by_uid_r(PasswdCache* cache, uid_t uid,
                                       struct passwd* result, char* buffer,
                                       size_t buflen, int* errnop);
enum nss_status lookup_passwd_by_name_r(PasswdCache* cache, const char* name,
                                        struct passwd* result, char* buffer,
                                        size_t buflen, int* errnop);

// State for iterating through passwd entries, for getpwent_r implementation.
typedef struct {
  // Internal state: offset of the next line to read in cache text section.
  uint64_t internal_offset_;
} PasswdCacheIter;

// Initialize iterator state for setpwent.
void passwd_cache_iter_begin(PasswdCache* cache, PasswdCacheIter* iter);

// Get next entry for getpwent_r.
// Reads entry and advances iterator.
enum nss_status passwd_cache_iter_next_r(PasswdCache* cache,
                                         PasswdCacheIter* iter,
                                         struct passwd* result, char* buffer,
                                         size_t buflen, int* errnop);

// Functions to inspect cache header for testing.
uint64_t get_passwd_cache_uid_count(PasswdCache* cache);
uint64_t get_passwd_cache_name_count(PasswdCache* cache);

#ifdef __cplusplus
}
#endif

#endif  /* OSLOGIN_PASSWD_CACHE_READER_H */
