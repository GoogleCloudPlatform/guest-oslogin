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

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <ios>
#include <string>

#include "include/compat.h"
#include "include/oslogin_passwd_cache_writer.h"
#include "include/oslogin_utils.h"

using oslogin_utils::BufferManager;
using oslogin_utils::NssCache;

// File paths for the nss cache file.
static const char kDefaultFilePath[] = K_DEFAULT_PFILE_PATH;
static const char kDefaultBackupFilePath[] = K_DEFAULT_BACKUP_PFILE_PATH;

// Local NSS Cache size. This affects the maximum number of passwd
// entries per http request.
static const uint64_t kNssPasswdCacheSize = 2048;

// Passwd buffer size. We are guaranteed that a single OS Login user will not
// exceed 32k.
static const uint64_t kPasswdBufferSize = 32768;

int refreshpasswdcache(bool cloud_run) {
  syslog(LOG_INFO, "Refreshing passwd entry cache");
  int error_code = 0;
  // Temporary buffer to hold passwd entries before writing.
  char buffer[kPasswdBufferSize];
  struct passwd pwd;
  NssCache nss_cache(kNssPasswdCacheSize);

  OsLoginPasswdCacheWriter passwd_cache_writer;

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
      pwd.pw_passwd = (char*)"*";
    }
    // Cloud Run logs in the user as root.
    if (cloud_run) {
      pwd.pw_dir = (char*)"/";
      pwd.pw_uid = 0;
      pwd.pw_gid = 0;
    }
    passwd_cache_writer.AddUser(pwd.pw_name, pwd.pw_passwd, pwd.pw_uid,
                                pwd.pw_gid, pwd.pw_gecos, pwd.pw_dir,
                                pwd.pw_shell);
  }

  if (error_code == ENOMSG) {
    return 0;
  } else if (error_code == ENOENT) {
    syslog(LOG_ERR, "Failed to get users, not updating passwd cache file.");
    // If the cache file already exists, we don't want to overwrite it on a
    // server error.
    struct stat buffer;
    if (stat(kDefaultFilePath, &buffer) == 0) {
      return 0;
    }
  }

  std::ofstream cache_file(kDefaultBackupFilePath, std::ios::binary);
  if (!passwd_cache_writer.Commit(cache_file)) {
    syslog(LOG_ERR, "Failed to commit passwd cache file.");
    cache_file.close();
    remove(kDefaultBackupFilePath);
    return -1;
  }
  try {
    cache_file.close();
  } catch (const std::ofstream::failure &e) {
    syslog(LOG_ERR, "Exception closing file");
    error_code = ENOENT;
  }
  if (error_code == ENOENT) {
    remove(kDefaultBackupFilePath);
    return -1;
  }
  if (rename(kDefaultBackupFilePath, kDefaultFilePath) != 0) {
    syslog(LOG_ERR, "Error moving %s to %s: %s", kDefaultBackupFilePath,
          kDefaultFilePath, strerror(errno));
    remove(kDefaultBackupFilePath);
    return -1;
  }
  if (chown(kDefaultFilePath, 0, 0) != 0) {
    syslog(LOG_ERR, "Failed to chown passwd cache file %s: %s",
          kDefaultFilePath, strerror(errno));
    remove(kDefaultFilePath);
    return -1;
  }
  if (chmod(kDefaultFilePath, 0644) != 0) {
    syslog(LOG_ERR, "Failed to chmod passwd cache file %s: %s",
          kDefaultFilePath, strerror(errno));
    remove(kDefaultFilePath);
    return -1;
  }

  return 0;
}

int main(int argc, char* argv[]) {
  bool cloud_run = false;
  openlog("oslogin_cache_refresh", LOG_PID|LOG_PERROR, LOG_USER);

  if (argc == 2) {
    if (strcmp(argv[1], "--cloud_run") == 0){
      cloud_run = true;
    } else {
      syslog(LOG_ERR, "Invalid input argument %s, Exiting.", argv[1]);
      return 1;
    }
  }

  int u_res = refreshpasswdcache(cloud_run);
  closelog();
  return u_res;
}
