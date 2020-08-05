// Copyright 2018 Google Inc. All Rights Reserved.
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

#include <errno.h>
#include <nss.h>
#include <pthread.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <sstream>

#include <fstream>

#include <compat.h>
#include <oslogin_utils.h>

using oslogin_utils::BufferManager;
using oslogin_utils::MutexLock;
using oslogin_utils::NssCache;
using oslogin_utils::GetUsersForGroup;

// File paths for the nss cache file.
static const char kDefaultFilePath[] = K_DEFAULT_PFILE_PATH;
static const char kDefaultBackupFilePath[] = K_DEFAULT_BACKUP_PFILE_PATH;
static const char kDefaultGroupPath[] = K_DEFAULT_GFILE_PATH;
static const char kDefaultBackupGroupPath[] = K_DEFAULT_BACKUP_GFILE_PATH;

// Local NSS Cache size. This affects the maximum number of passwd or group
// entries per http request.
static const uint64_t kNssGroupCacheSize = 499;
static const uint64_t kNssPasswdCacheSize = 2048;

// Passwd buffer size. We are guaranteed that a single OS Login user will not
// exceed 32k.
static const uint64_t kPasswdBufferSize = 32768;

int refreshpasswdcache() {
  syslog(LOG_INFO, "Refreshing passwd entry cache");
  int error_code = 0;
  // Temporary buffer to hold passwd entries before writing.
  char buffer[kPasswdBufferSize];
  struct passwd pwd;
  NssCache nss_cache(kNssPasswdCacheSize);


  std::ofstream cache_file(kDefaultBackupFilePath);
  if (cache_file.fail()) {
    syslog(LOG_ERR, "Failed to open file %s.", kDefaultBackupFilePath);
    return -1;
  }
  chown(kDefaultBackupFilePath, 0, 0);
  chmod(kDefaultBackupFilePath, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  int count = 0;
  nss_cache.Reset();
  while (!nss_cache.OnLastPage() || nss_cache.HasNextEntry()) {
    BufferManager buffer_manager(buffer, kPasswdBufferSize);
    if (!nss_cache.NssGetpwentHelper(&buffer_manager, &pwd, &error_code)) {
      if (error_code == ERANGE) {
        syslog(LOG_ERR, "passwd entry size out of range, skipping");
      } else if (error_code == EINVAL) {
        syslog(LOG_ERR, "Malformed passwd entry, skipping");
      } else if (error_code == ENOENT) {
        syslog(LOG_ERR, "Failure getting users, quitting");
        count = 0;
        break;
      }
      continue;
    }
    if (strlen(pwd.pw_passwd) == 0) {
      pwd.pw_passwd = (char *)"*";
    }
    cache_file << pwd.pw_name << ":" << pwd.pw_passwd << ":" << pwd.pw_uid
               << ":" << pwd.pw_gid << ":" << pwd.pw_gecos << ":" << pwd.pw_dir
               << ":" << pwd.pw_shell << "\n";
    count++;
  }
  cache_file.close();

  if (count > 0) {
    if (rename(kDefaultBackupFilePath, kDefaultFilePath) != 0) {
      syslog(LOG_ERR, "Could not move passwd cache file.");
      remove(kDefaultBackupFilePath);
    }
  } else {
    // count <= 0
    syslog(LOG_ERR, "Produced empty passwd cache file, removing %s.", kDefaultBackupFilePath);
    remove(kDefaultBackupFilePath);
  }

  return 0;
}

int refreshgroupcache() {
  syslog(LOG_INFO, "Refreshing group entry cache");
  int error_code = 0;
  // Temporary buffer to hold passwd entries before writing.
  char buffer[kPasswdBufferSize];
  NssCache nss_cache(kNssGroupCacheSize);

  std::ofstream cache_file(kDefaultBackupGroupPath);
  if (cache_file.fail()) {
    syslog(LOG_ERR, "Failed to open file %s.", kDefaultBackupGroupPath);
    return -1;
  }
  chown(kDefaultBackupGroupPath, 0, 0);
  chmod(kDefaultBackupGroupPath, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  struct group grp;
  int count = 0;
  nss_cache.Reset();
  std::vector<string> users;
  while (!nss_cache.OnLastPage() || nss_cache.HasNextEntry()) {
    BufferManager buffer_manager(buffer, kPasswdBufferSize);
    if (!nss_cache.NssGetgrentHelper(&buffer_manager, &grp, &error_code)) {
      if (error_code == ERANGE) {
        syslog(LOG_ERR, "Group entry size out of range, skipping");
      } else if (error_code == EINVAL) {
        syslog(LOG_ERR, "Malformed group entry, skipping");
      } else if (error_code == ENOENT) {
        syslog(LOG_ERR, "Failure getting groups, quitting");
        count = 0;
        break;
      }
      continue;
    }
    std::string name(grp.gr_name);
    if (!GetUsersForGroup(name, &users, &error_code)) {
      syslog(LOG_ERR,
             "Error getting users for group %s (error_code %d), skipping.",
             grp.gr_name, error_code);
      continue;
    }
    cache_file << grp.gr_name << ":" << grp.gr_passwd << ":" << grp.gr_gid << ":" << users.front();
    users.erase(users.begin());
    for (int i = 0; i < (int)users.size(); i++) {
      cache_file << "," << users[i];
    }
    cache_file << "\n";
    count++;
  }
  cache_file.close();

  if (count > 0) {
    if (rename(kDefaultBackupGroupPath, kDefaultGroupPath) != 0) {
      syslog(LOG_ERR, "Could not move group cache file.");
      remove(kDefaultBackupGroupPath);
    }
  } else {
    // count <= 0
    syslog(LOG_ERR, "Produced empty group cache file, removing %s.", kDefaultBackupGroupPath);
    remove(kDefaultBackupGroupPath);
  }

  return 0;
}

int main() {
  openlog("oslogin_cache_refresh", LOG_PID|LOG_PERROR, LOG_USER);
  int u_res, g_res;
  u_res = refreshpasswdcache();
  g_res = refreshgroupcache();
  closelog();
  if (u_res != 0)
    return u_res;
  return g_res;
}
