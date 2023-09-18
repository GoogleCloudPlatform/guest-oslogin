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
  cache_file << std::unitbuf; // enable automatic flushing
  chown(kDefaultBackupFilePath, 0, 0);
  chmod(kDefaultBackupFilePath, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

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
        break;
      } else if (error_code == ENOMSG) {
        // ENOMSG means OS Login is not enabled.
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
  }
  cache_file.close();

  if (error_code == ENOMSG) {
    remove(kDefaultBackupFilePath);
    return 0;
  } else if (error_code == ENOENT) {
    syslog(LOG_ERR, "Failed to get users, not updating passwd cache file, removing %s.", kDefaultBackupFilePath);
    // If the cache file already exists, we don't want to overwrite it on a
    // server error. So remove the backup file and return here.
    struct stat buffer;
    if (stat(kDefaultFilePath, &buffer) == 0) {
      remove(kDefaultBackupFilePath);
      return 0;
    }
  }

  if (rename(kDefaultBackupFilePath, kDefaultFilePath) != 0) {
    syslog(LOG_ERR, "Error moving %s to %s.", kDefaultBackupFilePath, kDefaultFilePath);
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
  cache_file << std::unitbuf; // enable automatic flushing
  cache_file.exceptions( cache_file.exceptions() | std::ofstream::failbit | std::ofstream::badbit );
  chown(kDefaultBackupGroupPath, 0, 0);
  chmod(kDefaultBackupGroupPath, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  struct group grp;
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
        break;
      } else if (error_code == ENOMSG) {
        // ENOMSG means OS Login is not enabled.
        break;
      }
      continue;
    }
    std::string name(grp.gr_name);
    users.clear();
    if (!GetUsersForGroup(name, &users, &error_code)) {
      syslog(LOG_ERR,
             "Error getting users for group %s (error_code %d), skipping.",
             grp.gr_name, error_code);
      continue;
    }
    try {
      cache_file << grp.gr_name << ":" << grp.gr_passwd << ":" << grp.gr_gid << ":";
      for (int i = 0; i < (int)users.size(); i++) {
        if (i > 0) {
          cache_file << ",";
        }
        cache_file << users[i];
      }
      cache_file << "\n";
    }
    catch (const std::ofstream::failure &e) {
      syslog(LOG_ERR, "Exception writing file");
      error_code = ENOENT;
      break;
    }
  }
  try {
    cache_file.close();
  }
  catch (const std::ofstream::failure &e) {
    syslog(LOG_ERR, "Exception closing file");
    error_code = ENOENT;
  }

  if (error_code == ENOMSG) {
    remove(kDefaultBackupGroupPath);
    return 0;
  } else if (error_code == ENOENT) {
    syslog(LOG_ERR, "Failed to get groups, not updating group cache file, removing %s.", kDefaultBackupGroupPath);
    // If the cache file already exists, we don't want to overwrite it on a
    // server error. So remove the backup file and return here.
    struct stat buffer;
    if (stat(kDefaultGroupPath, &buffer) == 0) {
      remove(kDefaultBackupGroupPath);
      return 0;
    }
  }

  if (rename(kDefaultBackupGroupPath, kDefaultGroupPath) != 0) {
    syslog(LOG_ERR, "Error moving %s to %s.", kDefaultBackupGroupPath, kDefaultGroupPath);
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
