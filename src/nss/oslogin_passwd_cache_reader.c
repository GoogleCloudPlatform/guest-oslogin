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

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <nss.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "include/oslogin_passwd_cache_reader.h"

// Eytzinger layout:
// Parent of k is (k-1)/2
// Left child of k is 2k+1
// Right child of k is 2k+2

struct passwd_cache_header {
  uint64_t uid_index_offset;
  uint64_t uid_index_len;
  uint64_t name_index_offset;
  uint64_t name_index_len;
  uint64_t text_offset;
  uint64_t text_len;
};

struct PasswdCache {
  void* map;
  size_t map_size;
  struct passwd_cache_header header;
};

// Because the file is a binary format, we need special functions to read
// multi-byte values from the file in the correct endianness.
static uint16_t read_le16(const uint8_t* p) {
  uint16_t val;
  memcpy(&val, p, sizeof(val));
  return le16toh(val);
}

static uint32_t read_le32(const uint8_t* p) {
  uint32_t val;
  memcpy(&val, p, sizeof(val));
  return le32toh(val);
}

static uint64_t read_le64(const uint8_t* p) {
  uint64_t val;
  memcpy(&val, p, sizeof(val));
  return le64toh(val);
}

PasswdCache* open_passwd_cache(const char* filename) {
  int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    return NULL;
  }

  struct stat st;
  if (fstat(fd, &st) == -1) {
    close(fd);
    return NULL;
  }

  void* map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  close(fd);
  if (map == MAP_FAILED) {
    return NULL;
  }

  PasswdCache* cache = (PasswdCache*)malloc(sizeof(PasswdCache));
  if (!cache) {
    munmap(map, st.st_size);
    return NULL;
  }

  cache->map = map;
  cache->map_size = st.st_size;

  // Read header
  uint8_t* p = (uint8_t*)map;
  cache->header.uid_index_offset = read_le64(p);
  cache->header.uid_index_len = read_le64(p + 8);
  cache->header.name_index_offset = read_le64(p + 16);
  cache->header.name_index_len = read_le64(p + 24);
  cache->header.text_offset = read_le64(p + 32);
  cache->header.text_len = read_le64(p + 40);

  // Basic validation
  if (cache->header.uid_index_offset < 48 ||
      cache->header.name_index_offset < cache->header.uid_index_offset ||
      cache->header.text_offset < cache->header.name_index_offset ||
      st.st_size < cache->header.text_offset + cache->header.text_len) {
    munmap(map, st.st_size);
    free(cache);
    return NULL;
  }

  return cache;
}

void close_passwd_cache(PasswdCache* cache) {
  if (cache) {
    munmap(cache->map, cache->map_size);
    free(cache);
  }
}

// Fills pwd struct and buf from passwd line.
// line_start points to mmap'd memory, line_len is line length excluding
// newline. Returns 0 on success, ERANGE if buffer too small, EINVAL if line
// format invalid.
static int parse_passwd_line_r(const char* line_start, size_t line_len,
                               struct passwd* pwd, char* buf, size_t buflen) {
  const char *token_start, *token_end;
  const char* line_ptr = line_start;
  const char* const line_end = line_start + line_len;
  char* buf_ptr = buf;
  int field_idx = 0;

  while (line_ptr <= line_end && field_idx < 7) {
    token_start = line_ptr;
    token_end = line_ptr;
    while (token_end < line_end && *token_end != ':') {
      token_end++;
    }
    size_t token_len = token_end - token_start;

    if (field_idx == 2 || field_idx == 3) {  // uid or gid
      char num_buf[21];                      // enough for 64-bit int
      if (token_len == 0 || token_len >= sizeof(num_buf)) return EINVAL;
      memcpy(num_buf, token_start, token_len);
      num_buf[token_len] = '\0';
      char* endp;
      unsigned long val = strtoul(num_buf, &endp, 10);
      if (*endp != '\0') return EINVAL;
      if (field_idx == 2) {
        pwd->pw_uid = val;
      } else {
        pwd->pw_gid = val;
      }
    } else {  // string field
      if ((buf + buflen) - buf_ptr < token_len + 1) return ERANGE;
      memcpy(buf_ptr, token_start, token_len);
      buf_ptr[token_len] = '\0';
      if (field_idx == 0)
        pwd->pw_name = buf_ptr;
      else if (field_idx == 1)
        pwd->pw_passwd = buf_ptr;
      else if (field_idx == 4)
        pwd->pw_gecos = buf_ptr;
      else if (field_idx == 5)
        pwd->pw_dir = buf_ptr;
      else if (field_idx == 6)
        pwd->pw_shell = buf_ptr;
      buf_ptr += token_len + 1;
    }

    field_idx++;
    line_ptr = token_end + 1;
  }

  if (field_idx != 7) return EINVAL;

  return 0;
}

struct line_info {
  const char* start;
  size_t len;
};

static int get_line_info(PasswdCache* cache, uint64_t offset,
                         struct line_info* info) {
  if (offset < cache->header.text_offset ||
      offset >= cache->header.text_offset + cache->header.text_len) {
    return -1;
  }
  size_t text_len = cache->header.text_len;
  const char* line_start = (const char*)cache->map + offset;
  size_t line_offset_in_text = offset - cache->header.text_offset;

  const char* nl =
      (const char*)memchr(line_start, '\n', text_len - line_offset_in_text);
  size_t len = nl ? (nl - line_start) : (text_len - line_offset_in_text);
  info->start = line_start;
  info->len = len;
  return 0;
}

enum nss_status lookup_passwd_by_uid_r(PasswdCache* cache, uid_t uid,
                                       struct passwd* result, char* buffer,
                                       size_t buflen, int* errnop) {
  if (!cache) {
    *errnop = ENOENT;
    return NSS_STATUS_UNAVAIL;
  }
  if (cache->header.uid_index_len == 0) {
    *errnop = 0;
    return NSS_STATUS_NOTFOUND;
  }

  size_t k = 0;
  uint8_t* base = (uint8_t*)cache->map + cache->header.uid_index_offset;
  size_t count = cache->header.uid_index_len;
  const size_t stride = 8 + 4;

  while (k < count) {
    uint32_t current_uid = read_le32(base + k * stride + 8);
    if (current_uid == uid) {
      uint64_t offset = read_le64(base + k * stride);
      struct line_info info;
      if (get_line_info(cache, offset, &info) != 0) {
        *errnop = EINVAL;
        return NSS_STATUS_TRYAGAIN;
      }
      int rc = parse_passwd_line_r(
          info.start, info.len, result, buffer, buflen);
      if (rc == 0) {
        *errnop = 0;
        return NSS_STATUS_SUCCESS;
      } else {
        *errnop = rc;
        return NSS_STATUS_TRYAGAIN;
      }
    } else if (uid < current_uid) {
      k = 2 * k + 1;
    } else {
      k = 2 * k + 2;
    }
  }
  *errnop = 0;
  return NSS_STATUS_NOTFOUND;
}

enum nss_status lookup_passwd_by_name_r(PasswdCache* cache, const char* name,
                                        struct passwd* result, char* buffer,
                                        size_t buflen, int* errnop) {
  if (!cache) {
    *errnop = ENOENT;
    return NSS_STATUS_UNAVAIL;
  }
  if (cache->header.name_index_len == 0) {
    *errnop = 0;
    return NSS_STATUS_NOTFOUND;
  }

  size_t name_len = strlen(name);
  uint64_t current_offset = cache->header.name_index_offset;
  uint8_t* base = (uint8_t*)cache->map;

  while (current_offset != 0 && current_offset < cache->header.text_offset) {
    uint64_t text_offset = read_le64(base + current_offset);
    uint64_t left_offset = read_le64(base + current_offset + 8);
    uint64_t right_offset = read_le64(base + current_offset + 16);
    uint16_t current_name_len = read_le16(base + current_offset + 24);
    const char* current_name = (const char*)(base + current_offset + 26);

    // The comparison logic here implements lexicographical string comparison
    // for BST traversal. We first compare up to the minimum length of the
    // two strings. If they are identical up to that point (cmp == 0),
    // it means one string is a prefix of the other, or they are identical.
    // In lexicographical order, the shorter string comes first, so if
    // lengths differ, we adjust cmp accordingly (e.g., "user" < "username").
    int cmp;
    size_t min_len = name_len < current_name_len ? name_len : current_name_len;
    cmp = memcmp(name, current_name, min_len);
    if (cmp == 0) {
      if (name_len == current_name_len) {
        struct line_info info;
        if (get_line_info(cache, text_offset, &info) != 0) {
          *errnop = EINVAL;
          return NSS_STATUS_TRYAGAIN;
        }
        int rc =
            parse_passwd_line_r(info.start, info.len, result, buffer, buflen);
        if (rc == 0) {
          *errnop = 0;
          return NSS_STATUS_SUCCESS;
        } else {
          *errnop = rc;
          return NSS_STATUS_TRYAGAIN;
        }
      }
      cmp = name_len < current_name_len ? -1 : 1;
    }

    if (cmp < 0) {
      current_offset = left_offset;
    } else {
      current_offset = right_offset;
    }
  }

  *errnop = 0;
  return NSS_STATUS_NOTFOUND;
}

void passwd_cache_iter_begin(PasswdCache* cache, PasswdCacheIter* iter) {
  if (cache && iter && cache->header.text_len > 0) {
    iter->internal_offset_ = cache->header.text_offset;
  } else if (iter) {
    iter->internal_offset_ = (uint64_t)-1;
  }
}

enum nss_status passwd_cache_iter_next_r(PasswdCache* cache,
                                         PasswdCacheIter* iter,
                                         struct passwd* result, char* buffer,
                                         size_t buflen, int* errnop) {
  if (!cache) {
    *errnop = ENOENT;
    return NSS_STATUS_UNAVAIL;
  }
  if (!iter || iter->internal_offset_ == (uint64_t)-1) {
    *errnop = 0;
    return NSS_STATUS_NOTFOUND;
  }
  if (iter->internal_offset_ < cache->header.text_offset ||
      iter->internal_offset_ >=
          cache->header.text_offset + cache->header.text_len) {
    // If offset is out of bounds for any reason, stop iteration.
    iter->internal_offset_ = (uint64_t)-1;
    *errnop = 0;
    return NSS_STATUS_NOTFOUND;
  }

  // Find line info for current offset
  size_t text_len = cache->header.text_len;
  const char* line_start = (const char*)cache->map + iter->internal_offset_;
  size_t line_offset_in_text =
      iter->internal_offset_ - cache->header.text_offset;
  const char* nl =
      (const char*)memchr(line_start, '\n', text_len - line_offset_in_text);
  size_t line_len = nl ? (nl - line_start) : (text_len - line_offset_in_text);

  // Parse entry
  int rc = parse_passwd_line_r(line_start, line_len, result, buffer, buflen);
  if (rc != 0) {
    *errnop = rc;
    return NSS_STATUS_TRYAGAIN;
  }

  // Advance iterator to start of next line, or -1 if end of text.
  if (nl) {
    iter->internal_offset_ = (nl + 1) - (const char*)cache->map;
    if (iter->internal_offset_ >=
        cache->header.text_offset + cache->header.text_len) {
      // If we are at or past the end, finish.
      iter->internal_offset_ = (uint64_t)-1;
    }
  } else {
    // No newline found, this must have been the last line.
    iter->internal_offset_ = (uint64_t)-1;
  }

  *errnop = 0;
  return NSS_STATUS_SUCCESS;
}

uint64_t get_passwd_cache_uid_count(PasswdCache* cache) {
  if (!cache) return 0;
  return cache->header.uid_index_len;
}

uint64_t get_passwd_cache_name_count(PasswdCache* cache) {
  if (!cache) return 0;
  return cache->header.name_index_len;
}
