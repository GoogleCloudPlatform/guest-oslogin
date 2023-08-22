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

#define PAM_SM_ACCOUNT
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <sstream>

#include <oslogin_utils.h>
#include <oslogin_sshca.h>

using oslogin_utils::kMetadataServerUrl;
using oslogin_utils::HttpGet;

extern "C" {

PAM_EXTERN int
pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) {
  return PAM_SUCCESS;
}

// BYOID authentication is a first in stack auth module set as sufficient, meaning that it
// will be ignored if failed and no other auth module will be checked if succeeded. The
// implementation accounts for 2fa module and certificate based authentication.

// if it's a cert based auth and it contains a BYOID fingerprint extension then we return success
// (ignoring other auth modules), otherwise it will return failure if 2fa is enabled
// or success if 2fa is disabled.
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc,
                    const char** argv) {
  const char *ssh_auth_info = NULL;
  char *fingerprint = NULL;
  bool twofactor = true;

  std::stringstream url;
  std::string response;
  long http_code = 0;
  url << kMetadataServerUrl << "project/attributes/enable-oslogin-2fa";

  // If we have 2fa enabled we must give a chance for 2fa module to authenticate, twofactor
  // variable will determine if we fail or succeed.
  if (!HttpGet(url.str(), &response, &http_code) || response.empty() || http_code != 200) {
    twofactor = false;
  }

  // Check if pam env var SSH_AUTH_INFO_0 is available and set - if 2fa is enabled ignore
  // the module, otherwise succeed and skip next auth modules.
  ssh_auth_info = pam_getenv(pamh, "SSH_AUTH_INFO_0");
  if (ssh_auth_info == NULL || strlen(ssh_auth_info) == 0) {
    if (twofactor) {
      return PAM_AUTHINFO_UNAVAIL;
    } else {
      return PAM_SUCCESS;
    }
  }

  // If the available auth info is a certificate and contains the BYOID fingerprint we
  // return success (skipping next auth modules).
  size_t fp_len = sshca_get_byoid_fingerprint(pamh, ssh_auth_info, &fingerprint);
  if (fp_len > 0) {
    return PAM_SUCCESS;
  }

  // No BYOID fingerprint certificate was found, fail the module if 2fa is enabled
  // giving a chance for the 2fa module to authenticate.
  if (twofactor) {
    return PAM_AUTHINFO_UNAVAIL;
  }

  // If 2fa is not enabled we succeed and skip next auth modules.
  return PAM_SUCCESS;
}

}
