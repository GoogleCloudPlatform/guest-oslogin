// Copyright 2024 Google Inc. All Rights Reserved.
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

#include <security/pam_modules.h>
#include <security/_pam_types.h>

#include <cstddef>
#include <cstdio>
#include <string>

#include "include/compat.h"
#include "include/oslogin_utils.h"

using std::string;

using oslogin_utils::AuthOptions;

extern "C" {

// pm_sm_acct_mgmt is the account management PAM implementation for admin users (or users
// with the proper loginAdmin policy). This account management module is intended for custom
// configuration handling only, where users need a way to in their stack configurations to
// differentiate a OS Login user. The Google Guest Agent will not manage the lifecycle of
// this module, it will not add this to the stack as part of the standard/default configuration
// set.
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv) {
  struct AuthOptions opts;
  const char *user_name;
  string user_response;

  if (pam_get_user(pamh, &user_name, NULL) != PAM_SUCCESS) {
    PAM_SYSLOG(pamh, LOG_INFO, "Could not get pam user.");
    return PAM_PERM_DENIED;
  }

  opts = {};
  opts.admin_policy_required = true;

  if (!AuthorizeUser(user_name, opts, &user_response)) {
    return PAM_PERM_DENIED;
  }

  return PAM_SUCCESS;
}

}
