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

#include <cstdlib>
#include <cstring>

#include "include/oslogin_sshca.h"
#include "include/oslogin_utils.h"
#include "openbsd-compat/base64.h"

using oslogin_utils::SysLogErr;

namespace oslogin_sshca {

typedef struct SSHCertType {
  const char *type;
  int (*SkipCustomField)(char **buff, size_t *blen);
} SSHCertType;

static int SkipDSAFields(char **buff, size_t *blen);
static int SkipECDSAFields(char **buff, size_t *blen);
static int SkipED25519Fields(char **buff, size_t *blen);
static int SkipRSAFields(char **buff, size_t *blen);

static SSHCertType sshca_impl[] = {
    {"ecdsa-sha2-nistp256-cert-v01@openssh.com", SkipECDSAFields},
    {"ecdsa-sha2-nistp384-cert-v01@openssh.com", SkipECDSAFields},
    {"ecdsa-sha2-nistp521-cert-v01@openssh.com", SkipECDSAFields},
    {"rsa-sha2-256-cert-v01@openssh.com", SkipRSAFields},
    {"rsa-sha2-512-cert-v01@openssh.com", SkipRSAFields},
    {"ssh-dss-cert-v01@openssh.com", SkipDSAFields},
    {"ssh-ed25519-cert-v01@openssh.com", SkipED25519Fields},
    {"ssh-rsa-cert-v01@openssh.com", SkipRSAFields},
    { },
};

static int GetString(char **buff, size_t *blen, char **ptr, size_t *len_ptr) {
  u_int32_t len;

  if (*blen < 4) {
    return -1;
  }

  len = PEEK_U32(*buff);
  if ((*blen - 4) < len) {
    return -1;
  }

  if (len_ptr != NULL) {
    *len_ptr = len;
  }

  *buff = *buff + 4;
  *blen = *blen - 4;

  if (ptr != NULL) {
    *ptr = (char *)malloc(len + 1);
    memcpy(*ptr, *buff, len);
    ((char *)*ptr)[len] = '\0';
  }

  // Always move the buffer forward.
  *buff = *buff + len;

  return 0;
}

static SSHCertType* GetImplementation(const char *type) {
  SSHCertType *iter;

  for (iter = sshca_impl; iter->type != NULL; iter++) {
    if (strcasecmp(type, iter->type) == 0) {
      return iter;
    }
  }

  return NULL;
}

static int SkipRSAFields(char **buff, size_t *blen) {
  // Skip e.
  if (GetString(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  // Skip n.
  if (GetString(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  return 0;
}

static int SkipDSAFields(char **buff, size_t *blen) {
  // Skip p.
  if (GetString(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  // Skip q.
  if (GetString(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  // Skip g.
  if (GetString(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  // Skip y.
  if (GetString(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  return 0;
}

static int SkipED25519Fields(char **buff, size_t *blen) {
  // Skip pk.
  return GetString(buff, blen, NULL, NULL);
}

static int SkipECDSAFields(char **buff, size_t *blen) {
  // Skip curve.
  if (GetString(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  // Skip public key.
  if (GetString(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  return 0;
}

static int GetExtension(const char *key, size_t k_len, char **exts) {
  SSHCertType* impl = NULL;
  size_t n_len, t_len, tmp_exts_len, ret = -1;
  char *tmp_exts, *tmp_head, *type, *key_b64, *head;

  head = tmp_head = NULL;

  head = key_b64 = (char *)calloc(k_len, sizeof(char));
  if (key_b64 == NULL) {
    SysLogErr("Could not allocate b64 buffer.");
    goto out;
  }

  if ((n_len = b64_pton(key, (u_char *)key_b64, k_len)) < 0) {
    SysLogErr("Could encode buffer b64.");
    goto out;
  }

  // Invalid key (?)
  if (n_len <= 4) {
    goto out;
  }

  if (GetString(&key_b64, &n_len, &type, &t_len) < 0) {
    SysLogErr("Could not get cert's type string.");
    goto out;
  }

  impl = GetImplementation(type);
  if (impl == NULL) {
    SysLogErr("Invalid cert type: %s.", type);
    goto out;
  }

  // Skip nonce for all types of certificates.
  if (GetString(&key_b64, &n_len, NULL, NULL) < 0) {
    SysLogErr("Failed to skip cert's \"nonce\" field.");
    goto out;
  }

  // Skip type specific fields.
  if (impl->SkipCustomField(&key_b64, &n_len) < 0) {
    SysLogErr("Failed to skip cert's custom/specific fields.");
    goto out;
  }

  // Skip serial.
  SKIP_UINT64(key_b64, n_len);

  // Skip type.
  SKIP_UINT32(key_b64, n_len);

  // Skip key id.
  if (GetString(&key_b64, &n_len, NULL, NULL) < 0) {
    SysLogErr("Failed to skip cert's \"key id\" field.");
    goto out;
  }

  // Skip valid principals.
  if (GetString(&key_b64, &n_len, NULL, NULL) < 0) {
    SysLogErr("Failed to skip cert's \"valid principals\" field.");
    goto out;
  }

  // Skip valid after.
  SKIP_UINT64(key_b64, n_len);

  // Skip valid before.
  SKIP_UINT64(key_b64, n_len);

  // Skip critical options.
  if (GetString(&key_b64, &n_len, NULL, NULL) < 0) {
    SysLogErr("Failed to skip cert's \"critical options\" field.");
    goto out;
  }

  // Get extensions buffer.
  if (GetString(&key_b64, &n_len, &tmp_exts, &tmp_exts_len) < 0) {
    SysLogErr("Failed to get cert's \"extensions\" field.");
    goto out;
  }

  // The field extensions is a self described/sized buffer.
  tmp_head = tmp_exts;
  if (GetString(&tmp_exts, &tmp_exts_len, exts, &ret) < 0) {
    SysLogErr("Failed to read Google's extension.");
    goto out;
  }

out:
  free(tmp_head);
  free(type);
  free(head);

  return ret;
}

static size_t ExtractFingerPrint(const char *extension, char **out) {
  const char *fingerprint_key = "fingerprint@google.com=";
  
  if (extension == NULL) {
    return 0;
  }

  const char *fingerprint_start = strstr(extension, fingerprint_key); 
  if (fingerprint_start == NULL) {
    return 0;
  }

  fingerprint_start += strlen(fingerprint_key);
  
  *out = strdup(fingerprint_start);
 
  return strlen(*out);
}

static int GetByoidFingerPrint(const char *blob, char **fingerprint) {
  size_t f_len, exts_len = -1;
  char *exts = NULL;

  exts_len = GetExtension(blob, strlen(blob), &exts);
  if (exts_len < 0) {
    SysLogErr("Could not parse/extract extension from SSH CA cert.");
    goto out;
  }

  f_len = ExtractFingerPrint(exts, fingerprint);
  if (f_len == 0) {
    SysLogErr("Could not parse/extract fingerprint from SSH CA cert's extension.");
    goto out;
  }

out:
  free(exts);

  return f_len;
}

int FingerPrintFromBlob(const char *blob, char **fingerprint) {
  if (blob == NULL || strlen(blob) == 0) {
    SysLogErr("Could not parse/extract fingerprint from SSH CA cert's extension: \"blob\" is empty.");
    return 0;
  }

  if (fingerprint == NULL) {
    SysLogErr("Could not parse/extract fingerprint from SSH CA cert's extension: \"fingerprint\" is NULL.");
    return 0;
  }

  return GetByoidFingerPrint(blob, fingerprint);
}

}
