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

#include <oslogin_sshca.h>
#include <openbsd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sshca_type {
  const char *type;
  int (*skip_custom_fields)(char **buff, size_t *blen);
} sshca_type;

static int _sshca_dsa_skip_fields(char **buff, size_t *blen);
static int _sshca_ecdsa_skip_fields(char **buff, size_t *blen);
static int _sshca_ed25519_skip_fields(char **buff, size_t *blen);
static int _sshca_rsa_skip_fields(char **buff, size_t *blen);

static sshca_type sshca_impl[] = {
    {"ecdsa-sha2-nistp256-cert-v01@openssh.com", _sshca_ecdsa_skip_fields},
    {"ecdsa-sha2-nistp384-cert-v01@openssh.com", _sshca_ecdsa_skip_fields},
    {"ecdsa-sha2-nistp521-cert-v01@openssh.com", _sshca_ecdsa_skip_fields},
    {"rsa-sha2-256-cert-v01@openssh.com", _sshca_rsa_skip_fields},
    {"rsa-sha2-512-cert-v01@openssh.com", _sshca_rsa_skip_fields},
    {"ssh-dss-cert-v01@openssh.com", _sshca_dsa_skip_fields},
    {"ssh-ed25519-cert-v01@openssh.com", _sshca_ed25519_skip_fields},
    {"ssh-rsa-cert-v01@openssh.com", _sshca_rsa_skip_fields},
    { },
};

static int
_sshca_get_string(char **buff, size_t *blen, char **ptr, size_t *len_ptr) {
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

static sshca_type*
_sshca_get_implementation(const char *type) {
  sshca_type *iter;

  for (iter = sshca_impl; iter->type != NULL; iter++) {
    if (strcasecmp(type, iter->type) == 0) {
      return iter;
    }
  }

  return NULL;
}

static int
_sshca_rsa_skip_fields(char **buff, size_t *blen) {
  // Skip e.
  if (_sshca_get_string(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  // Skip n.
  if (_sshca_get_string(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  return 0;
}

static int
_sshca_dsa_skip_fields(char **buff, size_t *blen) {
  // Skip p.
  if (_sshca_get_string(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  // Skip q.
  if (_sshca_get_string(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  // Skip g.
  if (_sshca_get_string(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  // Skip y.
  if (_sshca_get_string(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  return 0;
}

static int
_sshca_ed25519_skip_fields(char **buff, size_t *blen) {
  // Skip pk.
  return _sshca_get_string(buff, blen, NULL, NULL);
}

static int
_sshca_ecdsa_skip_fields(char **buff, size_t *blen) {
  // Skip curve.
  if (_sshca_get_string(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  // Skip public key.
  if (_sshca_get_string(buff, blen, NULL, NULL) < 0) {
    return -1;
  }

  return 0;
}

static int
_sshca_get_extension(pam_handle_t *pamh, const char *key, size_t k_len, char **exts) {
  sshca_type* impl = NULL;
  size_t n_len, t_len, tmp_exts_len, ret = -1;
  char *tmp_exts, *tmp_head, *type, *key_b64, *head;

  head = tmp_head = NULL;

  head = key_b64 = (char *)calloc(k_len, sizeof(char));
  if (key_b64 == NULL) {
    PAM_SYSLOG(pamh, LOG_ERR, "Could not allocate b64 buffer.");
    goto out;
  }

  if ((n_len = b64_pton(key, (u_char *)key_b64, k_len)) < 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Could encode buffer b64.");
    goto out;
  }

  // Invalid key (?)
  if (n_len <= 4) {
    goto out;
  }

  if (_sshca_get_string(&key_b64, &n_len, &type, &t_len) < 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Could not get cert's type string.");
    goto out;
  }

  impl = _sshca_get_implementation(type);
  if (impl == NULL) {
    PAM_SYSLOG(pamh, LOG_ERR, "Invalid cert type: %s.", type);
    goto out;
  }

  // Skip nonce for all types of certificates.
  if (_sshca_get_string(&key_b64, &n_len, NULL, NULL) < 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Failed to skip cert's \"nonce\" field.");
    goto out;
  }

  // Skip type specific fields.
  if (impl->skip_custom_fields(&key_b64, &n_len) < 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Failed to skip cert's custom/specific fields.");
    goto out;
  }

  // Skip serial.
  SKIP_UINT64(key_b64, n_len);

  // Skip type.
  SKIP_UINT32(key_b64, n_len);

  // Skip key id.
  if (_sshca_get_string(&key_b64, &n_len, NULL, NULL) < 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Failed to skip cert's \"key id\" field.");
    goto out;
  }

  // Skip valid principals.
  if (_sshca_get_string(&key_b64, &n_len, NULL, NULL) < 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Failed to skip cert's \"valid principals\" "
               "field.");
    goto out;
  }

  // Skip valid after.
  SKIP_UINT64(key_b64, n_len);

  // Skip valid before.
  SKIP_UINT64(key_b64, n_len);

  // Skip critical options.
  if (_sshca_get_string(&key_b64, &n_len, NULL, NULL) < 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Failed to skip cert's \"critical options\" "
               "field.");
    goto out;
  }

  // Get extensions buffer.
  if (_sshca_get_string(&key_b64, &n_len, &tmp_exts, &tmp_exts_len) < 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Failed to get cert's \"extensions\" field.");
    goto out;
  }

  // The field extensions is a self described/sized buffer.
  tmp_head = tmp_exts;
  if (_sshca_get_string(&tmp_exts, &tmp_exts_len, exts, &ret) < 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Failed to read google's extension.");
    goto out;
  }

out:
  free(tmp_head);
  free(type);
  free(head);

  return ret;
}

static size_t
_sshca_split_key(const char *blob, char **out) {
  int i, len, algo_start, k_start;
  char *key = NULL;

  len, k_start, algo_start = 0;

  for (i = 0; blob[i] != '\0'; i++) {
    if (blob[i] == ' ' && key == NULL) {
      if (!algo_start) {
        algo_start = i;
      } else {
        k_start = i + 1;
        key = (char *)blob + i + 1;
      }
    } else if (blob[i] == ' ' && key != NULL) {
      len = i;
    }
  }

  *out = strndup(key, len - k_start);
  return strlen(*out);
}

static size_t
_sshca_extract_fingerprint(const char *extension, char **out) {
  int i = 0;

  if (extension == NULL || strstr(extension, "fingerprint@google.com=") == NULL) {
    return 0;
  }

  for (i = 0; extension[i] != '\0'; i++) {
    if (extension[i] == '=') {
      *out = strdup(extension + i + 1);
    }
  }

  return i;
}

static int
_sshca_get_byoid_fingerprint(pam_handle_t *pamh, const char *blob, char **fingerprint) {
  size_t f_len, k_len, exts_len = -1;
  char *key, *exts = NULL;

  k_len = _sshca_split_key(blob, &key);
  if (k_len <= 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Could not split ssh ca cert.");
    goto out;
  }

  exts_len = _sshca_get_extension(pamh, key, k_len, &exts);
  if (exts_len < 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Could not parse/extract extension "
               "from ssh ca cert.");
    goto out;
  }

  f_len = _sshca_extract_fingerprint(exts, fingerprint);
  if (f_len == 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Could not parse/extract fingerprint "
               "from ssh ca cert's extension.");
    goto out;
  }

out:
  free(exts);
  free(key);

  return f_len;
}

int
sshca_get_byoid_fingerprint(pam_handle_t *pamh, const char *blob, char **fingerprint) {
  char *line, *saveptr = NULL;
  size_t f_len = 0;

  if (blob == NULL || strlen(blob) == 0) {
    PAM_SYSLOG(pamh, LOG_ERR, "Could not parse/extract fingerprint "
               "from ssh ca cert's extension: \"blob\" is empty.");
  }

  if (fingerprint == NULL) {
    PAM_SYSLOG(pamh, LOG_ERR, "Could not parse/extract fingerprint "
               "from ssh ca cert's extension: \"fingerprint\" is NULL.");
  }

  line = strtok_r((char *)blob, "\n", &saveptr);
  while (line != NULL) {
    f_len = _sshca_get_byoid_fingerprint(pamh, line, fingerprint);
    if (f_len > 0) {
      return f_len;
    }
    line = strtok_r(NULL, "\n", &saveptr);
  }

  return f_len;
}

#ifdef __cplusplus
}
#endif
