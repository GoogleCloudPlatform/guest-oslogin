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

#include <iostream>

#include <signal.h>

#include "include/oslogin_utils.h"
#include "include/oslogin_sshca.h"

using std::cout;
using std::endl;

using oslogin_sshca::FingerPrintFromBlob;

using oslogin_utils::AuthOptions;
using oslogin_utils::AuthorizeUser;
using oslogin_utils::CloseSysLog;
using oslogin_utils::FileName;
using oslogin_utils::SetupSysLog;
using oslogin_utils::SysLogErr;

#define SYSLOG_IDENT "sshd"
#define SUCCESS 0
#define FAIL    1

void signal_handler(int signo) {
  _Exit(0);
}

int main(int argc, char* argv[]) {
  size_t fp_len;
  char *user_name, *cert, *fingerprint;
  struct sigaction sig;
  struct AuthOptions opts;
  string user_response;
  const char *progname = FileName(argv[0]);

  fp_len = 0;
  opts = { 0 };
  user_name = cert = fingerprint = NULL;

  SetupSysLog(SYSLOG_IDENT, progname);

  if (argc != 3) {
    SysLogErr("usage: %s [username] [base64-encoded cert]", progname);
    goto fail;
  }

  sig = { 0 };
  sig.sa_handler = signal_handler;
  sigemptyset(&sig.sa_mask);

  if (sigaction(SIGPIPE, &sig, NULL) == -1) {
    SysLogErr("Unable to initialize signal handler. Exiting.");
    goto fail;
  }

  user_name = argv[1];
  cert = argv[2];

  fp_len = FingerPrintFromBlob(cert, &fingerprint);
  if (fp_len == 0) {
    SysLogErr("Could not extract/parse fingerprint from certificate.");
    goto fail;
  }

  opts.fingerprint = fingerprint;
  opts.fp_len = fp_len;

  if (AuthorizeUser(user_name, opts, &user_response)) {
    cout << user_name << endl;
  }

  free(fingerprint);
  CloseSysLog();

  return SUCCESS;

fail:
  CloseSysLog();
  return FAIL;
}
