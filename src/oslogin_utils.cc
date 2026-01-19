// Copyright 2019 Google Inc. All Rights Reserved.
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

// Requires libcurl4-openssl-dev, libjson-c5, and libjson-c-dev
#include <curl/curl.h>
#include <curl/easy.h>
#include <errno.h>
#include <grp.h>
#include <json.h>
#include <nss.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>

#if defined(__clang__) || __GNUC__ > 4 || \
    (__GNUC__ == 4 &&                     \
     (__GNUC_MINOR__ > 9 || (__GNUC_MINOR__ == 9 && __GNUC_PATCHLEVEL__ > 0)))
#include <regex>
#define Regex std
#else
#include <boost/regex.hpp>
#define Regex boost
#endif

#include "include/compat.h"
#include "include/oslogin_utils.h"

using std::string;

// Maximum number of retries for HTTP requests.
const int kMaxRetries = 3;

// Backoff duration 1 sec between retries.
const int kBackoffDuration = 1;

// Regex for validating user names.
static const char kUserNameRegex[] = "^[a-zA-Z0-9._][a-zA-Z0-9._-]{0,31}$";
static const char kSudoersDir[] = "/var/google-sudoers.d/";
static const char kUsersDir[] = "/var/google-users.d/";

namespace oslogin_utils {

// SysLog wraps syslog operations.
class SysLog {
 private:
  // app is the application name or the application prefix.
  const char *app;
 public:
  // Prints out an error to syslog.
  void Error(const char *fmt, va_list args);

  // Closes the file descriptor being used to write to sys logger.
  void Close();

  // Creates a SysLog instance specifying the ident. Additionally
  // it carries an app identifier, so the syslog entries will look like:
  // <<ident>>: <<app>>: <<Message>>
  // For google_authorized_keys for example, it would look like:
  // sshd: google_authorized_keys: <<Message>>
  SysLog(const char *ident, const char *app);
};

static SysLog *logger = NULL;

// ----------------- SysLog -------------------------
SysLog::SysLog(const char *ident, const char *app) {
  openlog(ident, LOG_PID|LOG_PERROR, LOG_DAEMON);
  this->app = app;
}

void SysLog::Error(const char *fmt, va_list args) {
  std::stringstream new_fmt;
  new_fmt << this->app << ": " << fmt;
  vsyslog(LOG_ERR, new_fmt.str().c_str(), args);
}

void SysLog::Close() {
  closelog();
}

void SetupSysLog(const char *ident, const char *app) {
  if (ident != NULL && logger == NULL) {
    logger = new SysLog(ident, app);
  }
}

void SysLogErr(const char *fmt, ...) {
  if (logger != NULL) {
    va_list args;
    va_start(args, fmt);
    logger->Error(fmt, args);
    va_end(args);
  }
}

void CloseSysLog() {
  if (logger != NULL) {
    logger->Close();
    logger = NULL;
  }
}

// ----------------- Buffer Manager -----------------

BufferManager::BufferManager(char* buf, size_t buflen)
    : buf_(buf), buflen_(buflen) {}

bool BufferManager::AppendString(const string& value, char** buffer, int* errnop) {
  size_t bytes_to_write = value.length() + 1;
  *buffer = static_cast<char*>(Reserve(bytes_to_write, errnop));
  if (*buffer == NULL) {
    return false;
  }
  strncpy(*buffer, value.c_str(), bytes_to_write);
  return true;
}

bool BufferManager::CheckSpaceAvailable(size_t bytes_to_write) const {
  if (bytes_to_write > buflen_) {
    return false;
  }
  return true;
}

void* BufferManager::Reserve(size_t bytes, int* errnop) {
  if (!CheckSpaceAvailable(bytes)) {
    *errnop = ERANGE;
    return NULL;
  }
  void* result = buf_;
  buf_ += bytes;
  buflen_ -= bytes;

  return result;
}

// ----------------- NSS Cache helper -----------------

NssCache::NssCache(int cache_size)
    : cache_size_(cache_size),
      entry_cache_(cache_size),
      page_token_(""),
      index_(0),
      on_last_page_(false) {}

void NssCache::Reset() {
  page_token_ = "";
  index_ = 0;
  entry_cache_.clear();
  on_last_page_ = false;
}

bool NssCache::HasNextEntry() {
  return (index_ < entry_cache_.size()) && !entry_cache_[index_].empty();
}

bool NssCache::GetNextPasswd(BufferManager* buf, struct passwd* result, int* errnop) {
  if (!HasNextEntry()) {
    *errnop = ENOENT;
    return false;
  }
  string cached_passwd = entry_cache_[index_++];
  return ParseJsonToPasswd(cached_passwd, result, buf, errnop);
}

bool NssCache::GetNextGroup(BufferManager* buf, struct group* result, int* errnop) {
  if (!HasNextEntry()) {
    *errnop = ENOENT;
    return false;
  }
  string cached_passwd = entry_cache_[index_++];
  return ParseJsonToGroup(cached_passwd, result, buf, errnop);
}

// ParseJsonRoot is declared early here, away from the other parsing functions
// found later (in the "JSON Parsing" section), so LoadJsonUsersToCache can
// take advantage of the improved error handling ParseJsonRoot offers.
json_object* ParseJsonRoot(const string& json) {
  json_object* root = NULL;
  struct json_tokener* tok = json_tokener_new();

  root = json_tokener_parse_ex(tok, json.c_str(), -1);
  if (root == NULL) {
    enum json_tokener_error jerr = json_tokener_get_error(tok);
    string error_message = json_tokener_error_desc(jerr);
    SysLogErr("Failed to parse root JSON element: \"%s\", from input \"%s\"",
              error_message.c_str(), json.c_str());
  }

  json_tokener_free(tok);
  return root;
}

bool NssCache::LoadJsonUsersToCache(string response) {
  Reset();

  json_object* root = ParseJsonRoot(response);
  if (root == NULL) {
    return false;
  }

  bool ret = false;
  int arraylen = 0;
  json_object* login_profiles = NULL;

  // First grab the page token.
  json_object* page_token_object;
  if (json_object_object_get_ex(root, "nextPageToken", &page_token_object)) {
    page_token_ = json_object_get_string(page_token_object);
  } else {
    goto cleanup;
  }

  // A page_token of 0 means we are done. This response will not contain any
  // login profiles.
  if (page_token_ == "0") {
    page_token_ = "";
    on_last_page_ = true;
    ret = true;
    goto cleanup;
  }

  // Now grab all of the loginProfiles.
  if (!json_object_object_get_ex(root, "loginProfiles", &login_profiles)) {
    goto cleanup;
  }

  if (json_object_get_type(login_profiles) != json_type_array) {
    goto cleanup;
  }

  arraylen = json_object_array_length(login_profiles);
  if (arraylen == 0 || arraylen > cache_size_) {
    goto cleanup;
  }

  for (int i = 0; i < arraylen; i++) {
    json_object* profile = json_object_array_get_idx(login_profiles, i);
    entry_cache_.push_back(json_object_to_json_string_ext(profile, JSON_C_TO_STRING_PLAIN));
  }
  ret = true;

cleanup:
  json_object_put(root);
  return ret;
}

bool NssCache::LoadJsonGroupsToCache(string response, int* errnop) {
  Reset();
  *errnop = ENOENT;

  json_object* root = NULL;
  root = json_tokener_parse(response.c_str());
  if (root == NULL) {
    return false;
  }

  bool ret = false;
  int arraylen = 0;
  json_object* groups = NULL;

  // First grab the page token.
  json_object* page_token_object;
  if (json_object_object_get_ex(root, "nextPageToken", &page_token_object)) {
    page_token_ = json_object_get_string(page_token_object);
  } else {
    goto cleanup;
  }
  // A page_token of 0 for groups is different than for users. This is the last
  // page, but it WILL contain groups if there are any.
  if (page_token_ == "0") {
    on_last_page_ = true;
    page_token_ = "";
  }
  if (!json_object_object_get_ex(root, "posixGroups", &groups)) {
    // Valid JSON but no groups, set ENOMSG as a 'no groups' code.
    *errnop = ENOMSG;
    goto cleanup;
  }
  if (json_object_get_type(groups) != json_type_array) {
    goto cleanup;
  }
  arraylen = json_object_array_length(groups);
  if (arraylen == 0 || arraylen > cache_size_) {
    goto cleanup;
  }
  for (int i = 0; i < arraylen; i++) {
    json_object* group = json_object_array_get_idx(groups, i);
    entry_cache_.push_back(json_object_to_json_string_ext(group, JSON_C_TO_STRING_PLAIN));
  }
  ret = true;
  *errnop = 0;

cleanup:
  json_object_put(root);
  return ret;
}

// Gets the next entry from the cache, refreshing as needed. Returns true if a
// passwd entry was loaded into the result parameter. Returns false in all other
// cases, setting errno as follows:
//
// * EINVAL  - current user entry was malformed in some way.
// * ERANGE  - the page of results did not fit into the provided buffer.
// * ENOMSG  - a 404 error was received when contacting the metadata server, indicating that
//             OS Login is not enabled in the instance metadata.
// * ENOENT  - a general failure to load the cache occurred. Behavior of retries
//             following ENOENT is undefined.
bool NssCache::NssGetpwentHelper(BufferManager* buf, struct passwd* result, int* errnop) {
  if (!HasNextEntry() && !OnLastPage()) {
    std::stringstream url;
    url << kMetadataServerUrl << "users?pagesize=" << cache_size_;
    string page_token = GetPageToken();
    if (!page_token.empty()) {
      url << "&pagetoken=" << page_token;
    }
    string response;
    long http_code = 0;
    bool status = HttpGet(url.str(), &response, &http_code);
    // 404 means OS Login is not enabled.
    if (http_code == 404) {
      *errnop = ENOMSG;
      return false;
    }
    // General failure to load the cache occurred.
    if (!status || http_code != 200 || response.empty() || !LoadJsonUsersToCache(response)) {
      *errnop = ENOENT;
      return false;
    }
  }
  return (HasNextEntry() && GetNextPasswd(buf, result, errnop));
}

// Gets the next entry from the cache, refreshing as needed. Returns true if a
// group entry was loaded into the result parameter. Returns false in all other
// cases, setting errno as follows:
//
// * EINVAL  - current group entry was malformed in some way.
// * ERANGE  - the page of results did not fit into the provided buffer.
// * ENOMSG  - a 404 error was received when contacting the metadata server, indicating that
//             OS Login is not enabled in the instance metadata.
// * ENOENT  - a general failure to load the cache occurred. Behavior of retries
//             following ENOENT is undefined.
bool NssCache::NssGetgrentHelper(BufferManager* buf, struct group* result, int* errnop) {
  if (!HasNextEntry() && !OnLastPage()) {
    std::stringstream url;
    url << kMetadataServerUrl << "groups?pagesize=" << cache_size_;
    string page_token = GetPageToken();
    if (!page_token.empty()) {
      url << "&pagetoken=" << page_token;
    }
    string response;
    long http_code = 0;
    bool status = HttpGet(url.str(), &response, &http_code);
    // 404 means OS Login is not enabled.
    if (http_code == 404) {
      *errnop = ENOMSG;
      return false;
    }
    // Failed to make the request or empty response.
    if (!status || http_code != 200 || response.empty()) {
      *errnop = ENOENT;
      return false;
    }
    // General failure to load the cache occurred.
    if (!LoadJsonGroupsToCache(response, errnop)) {
      return false;
    }
  }

  if (!HasNextEntry() || !GetNextGroup(buf, result, errnop)) {
    return false;
  }

  std::vector<string> users;
  std::string name(result->gr_name);
  if (!GetUsersForGroup(name, &users, errnop)) {
    return false;
  }
  return AddUsersToGroup(users, result, buf, errnop);
}

// ----------------- HTTP functions -----------------

size_t OnCurlWrite(void* buf, size_t size, size_t nmemb, void* userp) {
  if (userp) {
    std::ostream& os = *static_cast<std::ostream*>(userp);
    std::streamsize len = size * nmemb;
    if (os.write(static_cast<char*>(buf), len)) {
      return len;
    }
  }
  return 0;
}

bool ShouldRetry(long http_code) {
  if (http_code == 200) {
    // Request returned successfully, no need to retry.
    return false;
  }
  if (http_code == 404) {
    // Metadata key does not exist, no point of retrying.
    return false;
  }
  if (http_code == 400) {
    // Request parameters are bad, no point of retrying.
    return false;
  }
  return true;
}

bool HttpDo(const string& url, const string& data, string* response, long* http_code) {
  if (response == NULL || http_code == NULL) {
    return false;
  }
  CURLcode code(CURLE_FAILED_INIT);
  curl_global_init(CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL);
  CURL* curl = curl_easy_init();
  std::ostringstream response_stream;
  int retry_count = 0;
  if (curl) {
    struct curl_slist* header_list = NULL;
    header_list = curl_slist_append(header_list, "Metadata-Flavor: Google");
    if (header_list == NULL) {
      curl_easy_cleanup(curl);
      curl_global_cleanup();
      return false;
    }
    do {
      // Apply backoff strategy before retrying.
      if (retry_count > 0) {
        sleep(kBackoffDuration);
      }
      response_stream.str("");
      response_stream.clear();
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &OnCurlWrite);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_stream);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
      curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
      if (data != "") {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
      }

      code = curl_easy_perform(curl);
      if (code != CURLE_OK) {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return false;
      }
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
    } while (retry_count++ < kMaxRetries && ShouldRetry(*http_code));
    curl_slist_free_all(header_list);
  }
  *response = response_stream.str();
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return true;
}

bool HttpGet(const string& url, string* response, long* http_code) {
  return HttpDo(url, "", response, http_code);
}

bool HttpPost(const string& url, const string& data, string* response, long* http_code) {
  return HttpDo(url, data, response, http_code);
}

string UrlEncode(const string& param) {
  CURL* curl = curl_easy_init();
  char* encoded = curl_easy_escape(curl, param.c_str(), param.length());
  if (encoded == NULL) {
    curl_easy_cleanup(curl);
    return "";
  }
  string encoded_param = encoded;
  curl_free(encoded);
  curl_easy_cleanup(curl);
  return encoded_param;
}

bool ValidateUserName(const string& user_name) {
  Regex::regex r(kUserNameRegex);
  return Regex::regex_match(user_name, r);
}

bool ValidatePasswd(struct passwd* result, BufferManager* buf, int* errnop) {
  // OS Login disallows uids less than 1000.
  if (result->pw_uid < 1000) {
    *errnop = EINVAL;
    return false;
  }
  if (result->pw_gid == 0) {
    *errnop = EINVAL;
    return false;
  }
  if (strlen(result->pw_name) == 0) {
    *errnop = EINVAL;
    return false;
  }
  if (strlen(result->pw_dir) == 0) {
    string home_dir = "/home/";
    home_dir.append(result->pw_name);
    if (!buf->AppendString(home_dir, &result->pw_dir, errnop)) {
      return false;
    }
  }
  if (strlen(result->pw_shell) == 0) {
    if (!buf->AppendString(DEFAULT_SHELL, &result->pw_shell, errnop)) {
      return false;
    }
  }
  if (strlen(result->pw_passwd) == 0) {
    if (!buf->AppendString(DEFAULT_PASSWD, &result->pw_passwd, errnop)) {
      return false;
    }
  }

  // OS Login reserves the GECOS field.
  if (!buf->AppendString("", &result->pw_gecos, errnop)) {
    return false;
  }

  return true;
}

// ----------------- JSON Parsing -----------------

bool ParseJsonToUsers(const string& json, std::vector<string>* result) {
  bool ret = false;

  json_object* root = ParseJsonRoot(json);
  if (root == NULL) {
    return ret;
  }
  json_object* users = NULL;
  if (!json_object_object_get_ex(root, "usernames", &users)) {
    ret = true; // means no users, not invalid.
    goto cleanup;
  }
  if (json_object_get_type(users) != json_type_array) {
    goto cleanup;
  }
  for (int idx=0; idx < (int)json_object_array_length(users); idx++) {
    json_object* user = json_object_array_get_idx(users, idx);
    const char* username = json_object_get_string(user);
    result->push_back(string(username));
  }
  ret = true;

cleanup:
  json_object_put(root);
  return ret;
}

bool ParseJsonToGroups(const string& json, std::vector<Group>* result) {
  bool ret = false;

  json_object* root = ParseJsonRoot(json);
  if (root == NULL) {
    return ret;
  }
  json_object* groups;
  json_type groupType;
  if (!json_object_object_get_ex(root, "posixGroups", &groups)) {
    SysLogErr("failed to parse POSIX groups from \"%s\"", json.c_str());
    goto cleanup;
  }
  groupType = json_object_get_type(groups);
  if (groupType != json_type_array) {
    SysLogErr("parsed unexpected type for field \"posixGroups\"; "
              "want a list, got %s", groupType);
    goto cleanup;
  }
  for (int idx = 0; idx < (int)json_object_array_length(groups); idx++) {
    json_object* group = json_object_array_get_idx(groups, idx);

    json_object* gid;
    if (!json_object_object_get_ex(group, "gid", &gid)) {
      SysLogErr("failed to parse gid from group %s", json_object_get_string(group));
      goto cleanup;
    }
    json_object* name;
    if (!json_object_object_get_ex(group, "name", &name)) {
      SysLogErr("failed to parse name from group %s", json_object_get_string(group));
      goto cleanup;
    }

    Group g;
    // We use json_object_get_int64 because GIDs are unsigned and may use all
    // 32 bits, but there is no json_object_get_uint32.
    // Because the GID should never exceed 32 bits, truncation is safe.
    g.gid = (uint32_t)json_object_get_int64(gid);

    // get_int64 will confusingly return 0 if the string can't be converted to
    // an integer. We can't rely on type check as it may be a string in the API.
    // Also 0 is invalid because it creates a 'root group'.
    if (g.gid == 0) {
      goto cleanup;
    }

    g.name = json_object_get_string(name);
    if (g.name == "") {
      goto cleanup;
    }

    result->push_back(g);
  }
  ret = true;

cleanup:
  json_object_put(root);
  return ret;
}

bool ParseJsonToGroup(const string& json, struct group* result, BufferManager*
                      buf, int* errnop) {
  bool ret = false;
  *errnop = EINVAL;
  int gr_gid = 65535;

  json_object* group = ParseJsonRoot(json);
  if (group == NULL) {
    return false;
  }

  json_object* gid;
  if (!json_object_object_get_ex(group, "gid", &gid)) {
    goto cleanup;
  }
  json_object* name;
  if (!json_object_object_get_ex(group, "name", &name)) {
    goto cleanup;
  }

  if ((gr_gid = json_object_get_int64(gid)) == 0) {
    goto cleanup;
  }

  result->gr_gid = gr_gid;
  if (!buf->AppendString("", &result->gr_passwd, errnop))
    goto cleanup;
  if (!buf->AppendString(json_object_get_string(name), &result->gr_name,
                         errnop))
    goto cleanup;

  *errnop = 0;
  ret = true;

cleanup:
  json_object_put(group);
  return ret;
}

std::vector<string> ParseJsonToSshKeys(const string& json) {
  std::vector<string> result;
  json_object* root = ParseJsonRoot(json);
  if (root == NULL) {
    return result;
  }

  // Locate the sshPublicKeys object.
  json_object* login_profiles;
  if (!json_object_object_get_ex(root, "loginProfiles", &login_profiles)) {
    goto cleanup;
  }
  if (json_object_get_type(login_profiles) != json_type_array) {
    goto cleanup;
  }
  login_profiles = json_object_array_get_idx(login_profiles, 0);

  json_object* ssh_public_keys;
  if (!json_object_object_get_ex(login_profiles, "sshPublicKeys", &ssh_public_keys)) {
    goto cleanup;
  }

  if (json_object_get_type(ssh_public_keys) != json_type_object) {
    goto cleanup;
  }

  {
  // Extra braces to indicate scope of key, obj below to compiler. Otherwise
  // g++ complains that `goto` bypasses initializers.
  json_object_object_foreach(ssh_public_keys, key, obj) {
    (void)(key);
    if (json_object_get_type(obj) != json_type_object) {
      continue;
    }
    string key_to_add = "";
    bool expired = false;
    json_object_object_foreach(obj, key, val) {
      string string_key(key);
      int val_type = json_object_get_type(val);
      if (string_key == "key") {
        if (val_type != json_type_string) {
          continue;
        }
        key_to_add = json_object_get_string(val);
      }
      if (string_key == "expirationTimeUsec") {
        if (val_type == json_type_int || val_type == json_type_string) {
          uint64_t expiry_usec = (uint64_t)json_object_get_int64(val);
          struct timeval tp;
          gettimeofday(&tp, NULL);
          uint64_t cur_usec = tp.tv_sec * 1000000 + tp.tv_usec;
          expired = cur_usec > expiry_usec;
        } else {
          continue;
        }
      }
    }
    if (!key_to_add.empty() && !expired) {
      result.push_back(key_to_add);
    }
  }
  }

cleanup:
  json_object_put(root);
  return result;
}

std::vector<string> ParseJsonToSshKeysSk(const string& json) {
  std::vector<string> result;

  json_object* root = ParseJsonRoot(json);
  if (root == NULL) {
    return result;
  }

  // Locate the securityKeys array.
  json_object* login_profiles;
  if (!json_object_object_get_ex(root, "loginProfiles", &login_profiles)) {
    goto cleanup;
  }
  if (json_object_get_type(login_profiles) != json_type_array) {
    goto cleanup;
  }

  login_profiles = json_object_array_get_idx(login_profiles, 0);

  json_object* security_keys;
  if (!json_object_object_get_ex(login_profiles, "securityKeys", &security_keys)) {
    goto cleanup;
  }

  if (json_object_get_type(security_keys) != json_type_array) {
    goto cleanup;
  }

  {
    size_t number_of_keys = 0;
    size_t idx;
    json_object* security_key = NULL;
    json_object* public_key = NULL;
    string key_to_add = "";

    number_of_keys = json_object_array_length(security_keys);
    for (idx = 0; idx < number_of_keys; idx++) {
      security_key = json_object_array_get_idx(security_keys, idx);
      if (json_object_get_type(security_key) != json_type_object) {
        goto cleanup;
      }
      if (!json_object_object_get_ex(security_key, "publicKey", &public_key)) {
        goto cleanup;
      }

      key_to_add = json_object_get_string(public_key);
      result.push_back(key_to_add);
      key_to_add.clear();
    }
  }

cleanup:
  json_object_put(root);
  return result;
}

bool ParseJsonToPasswd(const string& json, struct passwd* result, BufferManager*
                       buf, int* errnop) {
  bool ret = false;
  *errnop = EINVAL;
  json_object* root = NULL;
  json_object* origroot = NULL;

  origroot = root = ParseJsonRoot(json);
  if (root == NULL) {
    return false;
  }

  json_object* posix_accounts;
  json_object* login_profiles;
  // If this is called from getpwent_r, loginProfiles won't be in the response.
  if (json_object_object_get_ex(root, "loginProfiles", &login_profiles)) {
    if (json_object_get_type(login_profiles) != json_type_array) {
      goto cleanup;
    }
    // This overwrites root but we still have origroot for cleanup;
    root = json_object_array_get_idx(login_profiles, 0);
  }
  // Locate the posixAccounts object.
  if (!json_object_object_get_ex(root, "posixAccounts", &posix_accounts)) {
    goto cleanup;
  }
  if (json_object_get_type(posix_accounts) != json_type_array) {
    goto cleanup;
  }
  posix_accounts = json_object_array_get_idx(posix_accounts, 0);

  // Populate with some default values that ValidatePasswd can detect if they
  // are not set.
  result->pw_uid = 0;
  result->pw_shell = (char*)"";
  result->pw_name = (char*)"";
  result->pw_dir = (char*)"";
  result->pw_passwd = (char*)"";

  // Iterate through the json response and populate the passwd struct.
  if (json_object_get_type(posix_accounts) != json_type_object) {
    goto cleanup;
  }
  {
  // Extra braces to indicate scope of key, obj below to compiler. Otherwise
  // g++ complains that `goto` bypasses initializers.
  json_object_object_foreach(posix_accounts, key, val) {
    int val_type = json_object_get_type(val);
    // Convert char* to c++ string for easier comparison.
    string string_key(key);

    if (string_key == "uid") {
      if (val_type == json_type_int || val_type == json_type_string) {
        result->pw_uid = (uint32_t)json_object_get_int64(val);
        if (result->pw_uid == 0) {
          goto cleanup;
        }
      } else {
        goto cleanup;
      }
    } else if (string_key == "gid") {
      if (val_type == json_type_int || val_type == json_type_string) {
        result->pw_gid = (uint32_t)json_object_get_int64(val);
        // Use the uid as the default group when gid is not set or is zero.
        if (result->pw_gid == 0) {
          result->pw_gid = result->pw_uid;
        }
      } else {
        goto cleanup;
      }
    } else if (string_key == "username") {
      if (val_type != json_type_string) {
        goto cleanup;
      }
      if (!buf->AppendString(json_object_get_string(val),
                             &result->pw_name, errnop)) {
        goto cleanup;
      }
    } else if (string_key == "homeDirectory") {
      if (val_type != json_type_string) {
        goto cleanup;
      }
      if (!buf->AppendString(json_object_get_string(val),
                             &result->pw_dir, errnop)) {
        goto cleanup;
      }
    } else if (string_key == "shell") {
      if (val_type != json_type_string) {
        goto cleanup;
      }
      if (!buf->AppendString(json_object_get_string(val),
                             &result->pw_shell, errnop)) {
        goto cleanup;
      }
    }
  }
  }
  *errnop = 0;
  ret = ValidatePasswd(result, buf, errnop);

cleanup:
  json_object_put(origroot);
  return ret;
}

bool AddUsersToGroup(std::vector<string> users, struct group* result,
                     BufferManager* buf, int* errnop) {
  if (users.size() < 1) {
    return true;
  }

  // Get some space for the char* array for number of users + 1 for NULL cap.
  char** bufp;
  if (!(bufp =
            (char**)buf->Reserve(sizeof(char*) * (users.size() + 1), errnop))) {
    return false;
  }
  result->gr_mem = bufp;

  for (int i = 0; i < (int)users.size(); i++) {
    if (!buf->AppendString(users[i], bufp, errnop)) {
      result->gr_mem = NULL;
      return false;
    }
    bufp++;
  }
  *bufp = NULL;  // End the array with a null pointer.

  return true;
}

bool ParseJsonToEmail(const string& json, string* email) {
  bool ret = false;

  json_object* root = ParseJsonRoot(json);
  if (root == NULL) {
    return ret;
  }

  // Locate the email object.
  json_object* login_profiles;
  json_object* json_email;
  if (!json_object_object_get_ex(root, "loginProfiles", &login_profiles)) {
    goto cleanup;
  }
  if (json_object_get_type(login_profiles) != json_type_array) {
    goto cleanup;
  }
  login_profiles = json_object_array_get_idx(login_profiles, 0);
  if (!json_object_object_get_ex(login_profiles, "name", &json_email)) {
    goto cleanup;
  }
  ret = true;
  *email = json_object_get_string(json_email);

cleanup:
  json_object_put(root);
  return ret;
}

bool ParseJsonToSuccess(const string& json) {
  json_object* root = ParseJsonRoot(json);
  if (root == NULL) {
    return false;
  }
  json_object* success = NULL;
  if (!json_object_object_get_ex(root, "success", &success)) {
    json_object_put(root);
    return false;
  }
  bool ret = (bool)json_object_get_boolean(success);
  json_object_put(root);
  return ret;
}

bool ParseJsonToKey(const string& json, const string& key, string* response) {
  bool ret = false;

  json_object* root = ParseJsonRoot(json);
  if (root == NULL) {
    return ret;
  }

  json_object* json_response = NULL;
  const char* c_response = NULL;
  if (!json_object_object_get_ex(root, key.c_str(), &json_response)) {
    goto cleanup;
  }

  if (!(c_response = json_object_get_string(json_response))) {
    goto cleanup;
  }

  *response = c_response;
  ret = true;

cleanup:
  json_object_put(root);
  return ret;
}

bool ParseJsonToChallenges(const string& json, std::vector<Challenge>* challenges) {
  bool ret = false;

  json_object* root = ParseJsonRoot(json);
  if (root == NULL) {
    return ret;
  }

  json_object* challengeId = NULL;
  json_object* challengeType = NULL;
  json_object* challengeStatus = NULL;
  json_object* jsonChallenges = NULL;
  if (!json_object_object_get_ex(root, "challenges", &jsonChallenges)) {
    goto cleanup;
  }

  for (int i = 0; i < (int)json_object_array_length(jsonChallenges); ++i) {
    if (!json_object_object_get_ex(json_object_array_get_idx(jsonChallenges, i),
                                   "challengeId", &challengeId)) {
      goto cleanup;
    }
    if (!json_object_object_get_ex(json_object_array_get_idx(jsonChallenges, i),
                                   "challengeType", &challengeType)) {
      goto cleanup;
    }
    if (!json_object_object_get_ex(json_object_array_get_idx(jsonChallenges, i),
                                   "status", &challengeStatus)) {
      goto cleanup;
    }
    Challenge challenge;
    challenge.id = json_object_get_int(challengeId);
    challenge.type = json_object_get_string(challengeType);
    challenge.status = json_object_get_string(challengeStatus);

    challenges->push_back(challenge);
  }
  ret = true;

cleanup:
  json_object_put(root);
  return ret;
}

// ----------------- OS Login functions -----------------


bool GetGroupsForUser(string username, std::vector<Group>* groups, int* errnop) {
  string response;
  if (!(GetUser(username, &response))) {
    DEBUG("GetGroupsForUser: !GetUser\n");
    *errnop = ENOENT;
    return false;
  }

  string email;
  if (!ParseJsonToEmail(response, &email) || email.empty()) {
    DEBUG("GetGroupsForUser: !ParseJsonToEmail\n");
    *errnop = ENOENT;
    return false;
  }

  std::stringstream url;

  long http_code;
  string pageToken ("");

  do {
    url.str("");
    url << kMetadataServerUrl << "groups?email=" << email;
    if (pageToken != "")
      url << "&pagetoken=" << pageToken;

    response.clear();
    http_code = 0;
    if (!HttpGet(url.str(), &response, &http_code) || http_code != 200 ||
        response.empty()) {
      *errnop = EAGAIN;
      return false;
    }

    if (!ParseJsonToKey(response, "nextPageToken", &pageToken)) {
      *errnop = ENOENT;
      return false;
    }

    if (!ParseJsonToGroups(response, groups)) {
      *errnop = ENOENT;
      return false;
    }
  } while (pageToken != "0");
  return true;
}

bool GetGroupByName(string name, struct group* result, BufferManager* buf, int* errnop) {
  std::stringstream url;
  std::vector<Group> groups;

  string response;
  long http_code;

  url.str("");
  url << kMetadataServerUrl << "groups?groupname=" << name;

  response.clear();
  http_code = 0;
  if (!HttpGet(url.str(), &response, &http_code) || http_code != 200 ||
      response.empty()) {
    *errnop = EAGAIN;
    return false;
  }

  groups.clear();
  if (!ParseJsonToGroups(response, &groups) || groups.empty() || groups.size() != 1) {
    *errnop = ENOENT;
    return false;
  }

  Group el = groups[0];
  result->gr_gid = el.gid;
  if (!buf->AppendString(el.name, &result->gr_name, errnop)) {
    return false;
  }

  return true;
}

bool GetGroupByGID(uint32_t gid, struct group* result, BufferManager* buf, int* errnop) {
  std::stringstream url;
  std::vector<Group> groups;

  string response;
  long http_code;

  url.str("");
  url << kMetadataServerUrl << "groups?gid=" << gid;

  response.clear();
  http_code = 0;
  if (!HttpGet(url.str(), &response, &http_code) || http_code != 200 ||
      response.empty()) {
    *errnop = EAGAIN;
    return false;
  }

  groups.clear();
  if (!ParseJsonToGroups(response, &groups) || groups.empty() || groups.size() != 1) {
    *errnop = ENOENT;
    return false;
  }

  Group el = groups[0];
  result->gr_gid = el.gid;
  if (!buf->AppendString(el.name, &result->gr_name, errnop)) {
    return false;
  }

  return true;
}

bool GetUsersForGroup(string groupname, std::vector<string>* users, int* errnop) {
  string response;
  long http_code;
  string pageToken ("");
  std::stringstream url;

  do {
    url.str("");
    url << kMetadataServerUrl << "users?groupname=" << groupname;
    if (pageToken != "")
      url << "&pagetoken=" << pageToken;

    response.clear();
    http_code = 0;
    if (!HttpGet(url.str(), &response, &http_code) || http_code != 200 ||
        response.empty()) {
      *errnop = EAGAIN;
      return false;
    }
    if (!ParseJsonToKey(response, "nextPageToken", &pageToken)) {
      *errnop = EINVAL;
      return false;
    }
    if (!ParseJsonToUsers(response, users)) {
      *errnop = EINVAL;
      return false;
    }
  } while (pageToken != "0");
  return true;
}

bool MDSGetUser(const string& username, bool security_key, string* response) {
  std::stringstream url;
  url << kMetadataServerUrl << "users?username=" << UrlEncode(username);

  if (security_key) {
    url << "&view=securityKey";
  }

  long http_code = 0;
  if (!HttpGet(url.str(), response, &http_code) || response->empty() ||
      http_code != 200) {
    return false;
  }

  return true;
}

bool GetUser(const string& username, string* response) {
  return MDSGetUser(username, false, response);
}

bool StartSession(const string& email, string* response) {
  bool ret = true;
  json_object* jobj = NULL;
  json_object* jarr = NULL;

  jarr = json_object_new_array();
  json_object_array_add(jarr, json_object_new_string(INTERNAL_TWO_FACTOR));
  json_object_array_add(jarr, json_object_new_string(SECURITY_KEY_OTP));
  json_object_array_add(jarr, json_object_new_string(AUTHZEN));
  json_object_array_add(jarr, json_object_new_string(TOTP));
  json_object_array_add(jarr, json_object_new_string(IDV_PREREGISTERED_PHONE));

  jobj = json_object_new_object();
  json_object_object_add(jobj, "email", json_object_new_string(email.c_str()));
  json_object_object_add(jobj, "supportedChallengeTypes", jarr);  // Ownership transferred to jobj.

  const char* data;
  data = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);

  std::stringstream url;
  url << kMetadataServerUrl << "authenticate/sessions/start";

  long http_code = 0;
  if (!HttpPost(url.str(), data, response, &http_code) || response->empty() ||
      http_code != 200) {
    ret = false;
  }

  json_object_put(jobj);

  return ret;
}

bool ContinueSession(bool alt, const string& email, const string& user_token, const string& session_id, const Challenge& challenge, string* response) {
  bool ret = true;
  json_object* jobj = NULL;
  json_object* jresp = NULL;

  jobj = json_object_new_object();
  json_object_object_add(jobj, "email", json_object_new_string(email.c_str()));
  json_object_object_add(jobj, "challengeId",
                         json_object_new_int(challenge.id));

  if (alt) {
    json_object_object_add(jobj, "action",
                           json_object_new_string("START_ALTERNATE"));
  } else {
    json_object_object_add(jobj, "action", json_object_new_string("RESPOND"));
  }

  // AUTHZEN type and START_ALTERNATE action don't provide credentials.
  if (challenge.type != AUTHZEN && !alt) {
    jresp = json_object_new_object();
    json_object_object_add(jresp, "credential",
                           json_object_new_string(user_token.c_str()));
    json_object_object_add(jobj, "proposalResponse", jresp);  // Ownership transferred to jobj.
  }

  const char* data = NULL;
  data = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);

  std::stringstream url;
  url << kMetadataServerUrl << "authenticate/sessions/" << session_id
      << "/continue";
  long http_code = 0;
  if (!HttpPost(url.str(), data, response, &http_code) || response->empty() ||
      http_code != 200) {
    ret = false;
  }

  json_object_put(jobj);

  return ret;
}

static bool ApplyPolicy(const char *user_name, string email, const char *policy, struct AuthOptions opts) {
  std::stringstream url;
  url << kMetadataServerUrl << "authorize?email=" << UrlEncode(email) << "&policy=" << policy;

  // Don't try to add fingerprint parameter to policy call if we don't have it.
  if (opts.fp_len > 0) {
    url << "&fingerprint=" << opts.fingerprint;
  }

  string response;
  long http_code = 0;
  // Invalid user, just leave from here - the principal will not be allowed/authorized.
  if (!HttpGet(url.str(), &response, &http_code)) {
    SysLogErr("Failed to validate that OS Login user %s has %s permission.", user_name, policy);
    return false;
  }

  if (http_code != 200) {
    SysLogErr("Failed to validate that OS Login user %s has %s permission; "
              "got HTTP response code: %lu; got HTTP response body: %s",
              user_name, policy, http_code, response);
    return false;
  }

  if (!ParseJsonToSuccess(response)) {
    SysLogErr("OS Login user %s does not have %s permission.", user_name, policy);
    return false;
  }

  return true;
}

static bool FileExists(const char *file_path) {
  struct stat buff;
  return !stat(file_path, &buff);
}

static bool CreateGoogleUserFile(string users_filedir, string user_name) {
  std::ofstream users_file;

  string users_filename = (users_filedir + user_name);
  users_file.open(users_filename.c_str());

  if (!users_file.is_open()) {
    // If we can't open the file (meaning we can't create it) we should report failure.
    return false;
  }

  // This file gets sourced by sshd_config.
  users_file << "Match User " + user_name + "\n";
  users_file << "        AuthorizedKeysFile /dev/null\n";

  // We are only creating the file so we could just close it here.
  users_file.close();

  chown(users_filename.c_str(), 0, 0);
  chmod(users_filename.c_str(), S_IRUSR | S_IWUSR | S_IRGRP);
  return true;
}

static bool CreateGoogleSudoersFile(string sudoers_filename, const char *user_name) {
  std::ofstream sudoers_file;

  sudoers_file.open(sudoers_filename.c_str());

  if (!sudoers_file.is_open()) {
    // If we can't open the file (meaning we can't create it) we should report failure.
    return false;
  }

  sudoers_file << user_name << " ALL=(ALL) NOPASSWD: ALL\n";
  sudoers_file.close();

  chown(sudoers_filename.c_str(), 0, 0);
  chmod(sudoers_filename.c_str(), S_IRUSR | S_IRGRP);
  return true;
}

bool AuthorizeUser(const char *user_name, struct AuthOptions opts, string *user_response, bool cloud_run) {
  bool users_file_exists, sudoers_exists;
  string email, users_filename, sudoers_filename;

  users_file_exists = sudoers_exists = false;

  if (!ValidateUserName(user_name)) {
    return false;
  }

  // Call MDS "users?username=" endpoint.
  if (!MDSGetUser(user_name, opts.security_key, user_response)) {
    return false;
  }

  if (!ParseJsonToEmail(*user_response, &email) || email.empty()) {
    return false;
  }

  // Only check adminLogin for cloud run. Skip file creations.
  if (cloud_run) {
    bool result = ApplyPolicy(user_name, email, "adminLogin", opts);
    if (!result) {
      SysLogErr("Could not grant root access to organization user: %s.", user_name);
    }
    return result;
  }

  users_filename = string(kUsersDir) + user_name;
  users_file_exists = FileExists(users_filename.c_str());

  if (!ApplyPolicy(user_name, email, "login", opts)) {
    // Couldn't apply "login" policy for user in question, log it and deny.
    SysLogErr("Could not grant access to organization user: %s.", user_name);
    if (users_file_exists) {
      remove(users_filename.c_str());
    }
    return false;
  }

  if (!users_file_exists && !CreateGoogleUserFile(kUsersDir, user_name)) {
    // If we can't create users file we can't grant access, log it and deny.
    SysLogErr("Failed to create user's file.");
    return false;
  }

  sudoers_filename = string(kSudoersDir) + user_name;
  sudoers_exists = FileExists(sudoers_filename.c_str());

  if (ApplyPolicy(user_name, email, "adminLogin", opts)) {
    // Best effort creating sudoers file, if we fail log it and grant access.
    if (!sudoers_exists && !CreateGoogleSudoersFile(sudoers_filename, user_name)) {
      SysLogErr("Could not grant sudo permissions to organization user %s."
                " Sudoers file %s is not writable.", user_name, sudoers_filename.c_str());
    }
  } else {
    remove(sudoers_filename.c_str());
    if (opts.admin_policy_required) {
      return false;
    }
  }

  return true;
}

const char *FileName(const char *file_path) {
  int res_start = 0;
  for (int i = 0; file_path[i] != '\0'; i++) {
    if (file_path[i] == '/') {
      res_start = i;
    }
  }

  if (res_start > 0) {
    return file_path + res_start + 1;
  }

  return file_path;
}
}  // namespace oslogin_utils
