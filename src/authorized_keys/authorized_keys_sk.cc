// Copyright 2023 Google Inc. All Rights Reserved.
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

#include <cstring>
#include <iostream>

#include <signal.h>

#include "include/oslogin_utils.h"

using std::cout;
using std::endl;

using oslogin_utils::AuthOptions;
using oslogin_utils::AuthorizeUser;
using oslogin_utils::CloseSysLog;
using oslogin_utils::FileName;
using oslogin_utils::ParseJsonToSshKeys;
using oslogin_utils::ParseJsonToSshKeysSk;
using oslogin_utils::SetupSysLog;
using oslogin_utils::SysLogErr;

#define SYSLOG_IDENT "sshd"
#define SUCCESS 0
#define FAIL    1

void signal_handler(int signo) {
  _Exit(0);
}

int main(int argc, char* argv[]) {
  struct AuthOptions opts;
  struct sigaction sig;
  char *user_name;
  string user_response;
  bool is_sa = false;
  const char *progname = FileName(argv[0]);

  SetupSysLog(SYSLOG_IDENT, progname);

  if (argc != 2) {
    SysLogErr("usage: %s [username]", progname);
    goto fail;
  }

  sig = {};
  sig.sa_handler = signal_handler;
  sigemptyset(&sig.sa_mask);

  if (sigaction(SIGPIPE, &sig, NULL) == -1) {
    SysLogErr("Unable to initialize signal handler. Exiting.");
    goto fail;
  }

  user_name = argv[1];
  is_sa = (strncmp(user_name, "sa_", 3) == 0);

  opts = { 0 };
  opts.security_key = true;

  if (AuthorizeUser(user_name, opts, &user_response)) {
    // At this point, we've verified the user can log in. Grab the ssh keys from
    // the user response.
    std::vector<string> ssh_keys;
    if (is_sa) {
      // Service accounts should continue to function when SK is enabled.
      ssh_keys = ParseJsonToSshKeys(user_response);
    } else {
      ssh_keys = ParseJsonToSshKeysSk(user_response);
    }

    // Print out all available keys.
    for (size_t i = 0; i < ssh_keys.size(); i++) {
      cout << ssh_keys[i] << endl;
    }
  }

  CloseSysLog();
  return SUCCESS;

fail:
  CloseSysLog();
  return FAIL;
}
