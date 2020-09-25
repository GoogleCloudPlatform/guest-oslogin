// Copyright 2020 Google Inc. All Rights Reserved.
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

#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>


#define MAX_GR_MEM 100
#define MAX_ARGLEN 100

#define PW_NAME 0
#define PW_PASSWD 1
#define PW_UID 2
#define PW_GID 3
#define PW_GECOS 4
#define PW_DIR 5
#define PW_SHELL 6
#define PW_END 7

#define GR_NAME 0
#define GR_PASSWD 1
#define GR_GID 2
#define GR_MEM 3
#define GR_END 4

#define SOCK_PATH "/var/run/oslogin"

#define BUFSIZE 1024
#define MAXBUFSIZE 32768

#define LEN(index) ((fields[index+1] - fields[index]) - 1)

#define COPYINT(index, inner_result) \
    do { \
      memset(buffer, 0, buflen); \
      memcpy(buffer, &str[fields[index]], LEN(index)); \
      buffer[LEN(index)+1] = '\0'; \
      inner_result = atoi(buffer); \
    } while(0)

#define COPYSTR(index, inner_result) \
    do { \
      inner_result = buffer; \
      memcpy(buffer, &str[fields[index]], LEN(index)); \
      buffer[LEN(index)+1] = '\0'; \
      buffer += LEN(index)+1; \
    } while(0)

#define MIN(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#define DEBUGF(...) \
    do { \
      fprintf (stderr, __VA_ARGS__); \
    } while(0)

int parsepasswd(char *str, struct passwd *result, char *buffer, size_t buflen) {
  int fields[PW_END+1] = {0};

  fields[PW_END] = strlen(str)+1;
  if (fields[PW_END] > (int)buflen) {
    return ERANGE;
  }

  int i, field;
  for(field = 1, i = 0; i < fields[PW_END]; i++) {
    if (str[i] == ':') {
      fields[field++] = i+1;
    }
  }

  if (field != PW_END) {
    return ENOENT;
  }

  COPYINT(PW_UID, result->pw_uid);
  COPYINT(PW_GID, result->pw_gid);

  memset(buffer, 0, fields[PW_END]);
  COPYSTR(PW_NAME, result->pw_name);
  COPYSTR(PW_PASSWD, result->pw_passwd);
  COPYSTR(PW_GECOS, result->pw_gecos);
  COPYSTR(PW_DIR, result->pw_dir);
  COPYSTR(PW_SHELL, result->pw_shell);

  return 0;
}

int parsegroup(char *str, struct group *result, char *buffer, size_t buflen) {
  int fields[GR_END+1] = {0};
  int members[MAX_GR_MEM] = {0};
  int i, field, len;
  char **bufp;

  // Check whether buffer can fit the string.
  fields[GR_END] = strlen(str)+1;
  if (fields[GR_END] > (int)buflen) {
    return ERANGE;
  }

  // Record field indexes.
  for(field = 1, i = 0; i < fields[GR_END]; i++) {
    if (str[i] == ':') {
      fields[field++] = i+1;
    }
  }

  // Wrong number of fields in record.
  if (field != GR_END) {
    return ENOENT;
  }

  // Record member indexes.
  members[0] = fields[GR_MEM];
  for(field = 1, i = fields[GR_MEM]; i < fields[GR_END]; i++) {
    if (str[i] == ',') {
      members[field++] = i+1;
    }
  }
  members[field] = fields[GR_END];

  // Check whether the buffer can fit the char* array.
  if ((fields[GR_END] + ((field+1) * sizeof(char *))) > buflen) {
    return ERANGE;
  }

  COPYINT(GR_GID, result->gr_gid);

  memset(buffer, 0, fields[GR_END]);
  COPYSTR(GR_NAME, result->gr_name);
  COPYSTR(GR_PASSWD, result->gr_passwd);

  result->gr_mem = bufp = (char **)buffer;
  buffer += (sizeof(char *) * (field + 1));

  for(i = 0; i < field; i++) {
    len = ((members[i+1] - members[i]) - 1);
    memcpy(buffer, &str[members[i]], len);
    buffer[len+1] = '\0';

    *(bufp++) = buffer;
    buffer += len+1;
  }
  *bufp = NULL;

  return 0;
}

struct Buffer {
  ssize_t buflen; // how much data we read into the buffer
  ssize_t bufsize; // allocated space for buffer
  char *buf;  // the buffer we copy results into
  int socket;
};

struct Buffer pwbuf;
struct Buffer grbuf;

int dial(struct Buffer *const buffer) {
  if (buffer->socket != 0) {
    return 0;
  }
  if ((buffer->socket = socket(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0)) == -1) {
    return -1;
  }

  int len;
  struct sockaddr_un remote;
  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, SOCK_PATH);
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(buffer->socket, (struct sockaddr *)&remote, len) == -1) {
      return -1;
  }

  return 0;
}

int recvline(struct Buffer *const buffer) {
  int res = 0;
  ssize_t recvlen, new_size = 0;
  fd_set fds;
  struct timeval tmout = {2,0};

  // TODO: catch malloc errors
  char *recvbuf = (char *)malloc(BUFSIZE);

  while(1) {
    FD_ZERO(&fds);
    FD_SET(buffer->socket, &fds);
    res = select(buffer->socket+1, &fds, NULL, NULL, &tmout);
    if (res <= 0 || !(FD_ISSET(buffer->socket, &fds))) {
      free(recvbuf);
      return -1;
    }
    if ((recvlen = recv(buffer->socket, recvbuf, BUFSIZE, 0)) <= 0) {
      free(recvbuf);
      return -1;
    }

    // Determine if buffer needs resizing.
    if ((buffer->buflen + recvlen) > buffer->bufsize) {
      new_size = MIN((buffer->bufsize * 2), MAXBUFSIZE);
      if (new_size == buffer->bufsize) {
        // We were already at limit!
        free(recvbuf);
        return -1;
      }
      if (realloc(buffer->buf, new_size) == NULL) {
        free(recvbuf);
        return -1;
      }
      buffer->bufsize = new_size;
    }

    memcpy(&(buffer->buf[buffer->buflen]), recvbuf, recvlen);
    buffer->buflen += recvlen;

    if (recvbuf[recvlen - 1] == '\n') {
      free(recvbuf);
      return buffer->buflen;
    }
  }

  free(recvbuf);
  return -1;  // Unreachable code.
}

static enum nss_status
_nss_oslogin_getpwnam_r(const char *name, struct passwd *result, char *buffer,
                        size_t buflen, int *errnop) {
  int res;
  struct Buffer mgr;
  memset(&mgr, 0, sizeof(struct Buffer));

  *errnop = 0;

  if (dial(&mgr) != 0) {
    *errnop = ENOENT;
    return NSS_STATUS_UNAVAIL;
  }

  // send the verb GETPWNAM with the argument <name>
  // TODO: validate incoming length of 'name' fits in 100 char
  char str[MAX_ARGLEN];
  sprintf(str, "GETPWNAM %s\n", name);
  if ((res = send(mgr.socket, str, strlen(str), 0)) == -1) {
    return NSS_STATUS_NOTFOUND;
  }

  mgr.bufsize = BUFSIZE;
  mgr.buf = (char *)malloc(BUFSIZE);
  if ((recvline(&mgr)) < 0) {
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  if (mgr.buf[0] == '\n') {
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  res = parsepasswd(mgr.buf, result, buffer, buflen);
  free(mgr.buf);
  if (res == 0) {
    return NSS_STATUS_SUCCESS;
  }
  *errnop = res;
  if (res == ERANGE) {
    return NSS_STATUS_TRYAGAIN;
  }
  return NSS_STATUS_NOTFOUND;
}

static enum nss_status
_nss_oslogin_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
                        size_t buflen, int *errnop) {
  int res;
  struct Buffer mgr;
  memset(&mgr, 0, sizeof(struct Buffer));

  *errnop = 0;

  if (dial(&mgr) != 0) {
    *errnop = ENOENT;
    return NSS_STATUS_UNAVAIL;
  }

  // send the verb GETPWUID with the argument <uid>
  // TODO: validate incoming length of 'uid' fits in 100 char
  char str[MAX_ARGLEN];
  sprintf(str, "GETPWUID %d\n", uid);
  if (send(mgr.socket, str, strlen(str), 0) == -1) {
      return NSS_STATUS_NOTFOUND;
  }

  mgr.bufsize = BUFSIZE;
  mgr.buf = (char *)malloc(BUFSIZE);
  if ((recvline(&mgr)) < 0) {
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  if (mgr.buf[0] == '\n') {
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  res = parsepasswd(mgr.buf, result, buffer, buflen);
  free(mgr.buf);
  if (res == 0) {
    return NSS_STATUS_SUCCESS;
  }
  *errnop = res;
  if (res == ERANGE) {
    return NSS_STATUS_TRYAGAIN;
  }
  return NSS_STATUS_NOTFOUND;
}

static enum nss_status
_nss_oslogin_getgrnam_r(const char *name, struct group *result, char *buffer,
                        size_t buflen, int *errnop) {
  int res;
  struct Buffer mgr;
  memset(&mgr, 0, sizeof(struct Buffer));
  *errnop = 0;

  if (dial(&mgr) != 0) {
    *errnop = ENOENT;
    return NSS_STATUS_UNAVAIL;
  }

  // send the verb GETPWNAM with the argument <name>
  // TODO: validate incoming length of 'name' fits in 100 char
  char str[MAX_ARGLEN];
  sprintf(str, "GETGRNAM %s\n", name);
  if (send(mgr.socket, str, strlen(str), 0) == -1) {
      return NSS_STATUS_NOTFOUND;
  }

  mgr.bufsize = BUFSIZE;
  mgr.buf = (char *)malloc(BUFSIZE);
  if ((recvline(&mgr)) < 0) {
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  if (mgr.buf[0] == '\n') {
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  res = parsegroup(mgr.buf, result, buffer, buflen);
  free(mgr.buf);
  if (res == 0) {
    return NSS_STATUS_SUCCESS;
  }
  *errnop = res;
  if (res == ERANGE) {
    return NSS_STATUS_TRYAGAIN;
  }
  return NSS_STATUS_NOTFOUND;
}

static enum nss_status
_nss_oslogin_getgrgid_r(gid_t gid, struct group *result, char *buffer,
                        size_t buflen, int *errnop) {
  int res;
  struct Buffer mgr;
  memset(&mgr, 0, sizeof(struct Buffer));

  *errnop = 0;

  if (dial(&mgr) != 0) {
    *errnop = ENOENT;
    return NSS_STATUS_UNAVAIL;
  }

  // send the verb GETGRGID with the argument <gid>
  char str[MAX_ARGLEN];
  sprintf(str, "GETGRGID %d\n", gid);
  if (send(mgr.socket, str, strlen(str), 0) == -1) {
      return NSS_STATUS_NOTFOUND;
  }

  mgr.bufsize = BUFSIZE;
  mgr.buf = (char *)malloc(BUFSIZE);
  if ((recvline(&mgr)) < 0) {
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  if (mgr.buf[0] == '\n') {
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  res = parsegroup(mgr.buf, result, buffer, buflen);
  free(mgr.buf);
  if (res == 0) {
    return NSS_STATUS_SUCCESS;
  }
  *errnop = res;
  if (res == ERANGE) {
    return NSS_STATUS_TRYAGAIN;
  }
  return NSS_STATUS_NOTFOUND;
}
