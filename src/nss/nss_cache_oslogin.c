// Copyright 2018 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// An NSS module which adds supports for file /etc/oslogin_passwd.cache
//
// This version is rewritten to be thread-safe and fully reentrant.
//
// Lookup functions (getpwnam_r, getpwuid_r, etc.) are implemented to be
// completely stateless. They open, read, and close the cache file on every
// call, preventing any side effects.
//
// Enumeration functions (setpwent, getpwent_r, endpwent) are inherently
// stateful by NSS design. To manage this state safely in a multithreaded
// environment, they use thread-local storage (`__thread`) for their file
// handles. This isolates each thread's enumeration, preventing interference.

#include <errno.h>
#include <nss.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#include "include/nss_cache_oslogin.h"
#include "include/compat.h"

// The NSS enumeration API (`set...ent`, `get...ent`, `end...ent`) is stateful.
// To ensure thread safety, the file pointers for enumeration must be
// thread-local. This gives each thread its own private file handle, preventing
// race conditions and interference from other threads or from the stateless
// lookup functions.
static __thread FILE *p_file_thread = NULL;
static __thread FILE *g_file_thread = NULL;

#ifdef BSD
extern int fgetpwent_r(FILE *, struct passwd *, char *, size_t,
                       struct passwd **);
extern int fgetgrent_r(FILE *, struct group *, char *, size_t, struct group **);
#endif // ifdef BSD

/* Common return code routine.
 * Returns TRYAGAIN if errnoval is ERANGE, so the caller can retry with a
 * larger buffer. Otherwise, returns NOTFOUND.
 */
static inline enum nss_status
_nss_cache_oslogin_ent_bad_return_code(int errnoval) {
    if (errnoval == ERANGE) {
        DEBUG("ERANGE: Try again with a bigger buffer\n");
        return NSS_STATUS_TRYAGAIN;
    }
    DEBUG("ENOENT or default case: Not found\n");
    return NSS_STATUS_NOTFOUND;
}

//
// Routines for passwd map
//

// _nss_cache_oslogin_setpwent()
// Called by NSS to open the passwd file for enumeration. Uses a thread-local
// file pointer to maintain state for the calling thread.
enum nss_status
_nss_cache_oslogin_setpwent(int stayopen) {
    DEBUG("Opening %s for enumeration\n", OSLOGIN_PASSWD_CACHE_PATH);
    if (p_file_thread) {
        fclose(p_file_thread);
    }
    p_file_thread = fopen(OSLOGIN_PASSWD_CACHE_PATH, "re");
    if (p_file_thread) {
        return NSS_STATUS_SUCCESS;
    }
    return NSS_STATUS_UNAVAIL;
}

// _nss_cache_oslogin_endpwent()
// Called by NSS to close the passwd enumeration file handle for the current thread.
enum nss_status
_nss_cache_oslogin_endpwent(void) {
    DEBUG("Closing %s for enumeration\n", OSLOGIN_PASSWD_CACHE_PATH);
    if (p_file_thread) {
        fclose(p_file_thread);
        p_file_thread = NULL;
    }
    return NSS_STATUS_SUCCESS;
}

// _nss_cache_oslogin_getpwent_r()
// Called by NSS to get the next entry from the passwd file, using the
// thread-local file pointer established by `setpwent`.
enum nss_status
_nss_cache_oslogin_getpwent_r(struct passwd *result, char *buffer,
                               size_t buflen, int *errnop) {
    if (p_file_thread == NULL) {
        if (_nss_cache_oslogin_setpwent(0) != NSS_STATUS_SUCCESS) {
            *errnop = errno;
            return NSS_STATUS_UNAVAIL;
        }
    }

    struct passwd *pwp = NULL;
    if (fgetpwent_r(p_file_thread, result, buffer, buflen, &pwp) == 0 && pwp != NULL) {
        DEBUG("Returning user %s (%u)\n", result->pw_name, result->pw_uid);
        return NSS_STATUS_SUCCESS;
    }

    *errnop = errno;
    if (*errnop == ENOENT) {
        *errnop = 0;
    }
    return _nss_cache_oslogin_ent_bad_return_code(*errnop);
}

// _nss_cache_oslogin_getpwuid_r()
// Stateless lookup for a user by UID. Opens, reads, and closes the file
// on each call. It has no side effects and does not interfere with enumerations.
enum nss_status
_nss_cache_oslogin_getpwuid_r(uid_t uid, struct passwd *result,
                               char *buffer, size_t buflen, int *errnop) {
    FILE *file = fopen(OSLOGIN_PASSWD_CACHE_PATH, "re");
    if (file == NULL) {
        *errnop = errno;
        return NSS_STATUS_UNAVAIL;
    }

    enum nss_status ret = NSS_STATUS_NOTFOUND;
    *errnop = 0;
    struct passwd *pwp = NULL;

    while (fgetpwent_r(file, result, buffer, buflen, &pwp) == 0 && pwp != NULL) {
        if (pwp->pw_uid == uid) {
            ret = NSS_STATUS_SUCCESS;
            break;
        }
    }

    if (pwp == NULL && errno != 0) {
        *errnop = errno;
        ret = _nss_cache_oslogin_ent_bad_return_code(*errnop);
    }

    fclose(file);
    return ret;
}

// _nss_cache_oslogin_getpwnam_r()
// Stateless lookup for a user by name.
enum nss_status
_nss_cache_oslogin_getpwnam_r(const char *name, struct passwd *result,
                               char *buffer, size_t buflen, int *errnop) {
    FILE *file = fopen(OSLOGIN_PASSWD_CACHE_PATH, "re");
    if (file == NULL) {
        *errnop = errno;
        return NSS_STATUS_UNAVAIL;
    }

    enum nss_status ret = NSS_STATUS_NOTFOUND;
    *errnop = 0;
    struct passwd *pwp = NULL;

    while (fgetpwent_r(file, result, buffer, buflen, &pwp) == 0 && pwp != NULL) {
        if (strcmp(pwp->pw_name, name) == 0) {
            ret = NSS_STATUS_SUCCESS;
            break;
        }
    }

    if (pwp == NULL && errno != 0) {
        *errnop = errno;
        ret = _nss_cache_oslogin_ent_bad_return_code(*errnop);
    }

    fclose(file);
    return ret;
}

//
// Routines for group map
//

// _nss_cache_oslogin_setgrent()
// Called by NSS to open the group file for enumeration. Uses a thread-local
// file pointer.
enum nss_status
_nss_cache_oslogin_setgrent(int stayopen) {
    DEBUG("Opening %s for enumeration\n", OSLOGIN_GROUP_CACHE_PATH);
    if (g_file_thread) {
        fclose(g_file_thread);
    }
    g_file_thread = fopen(OSLOGIN_GROUP_CACHE_PATH, "re");
    if (g_file_thread) {
        return NSS_STATUS_SUCCESS;
    }
    return NSS_STATUS_UNAVAIL;
}

// _nss_cache_oslogin_endgrent()
// Called by NSS to close the group enumeration file handle for the current thread.
enum nss_status
_nss_cache_oslogin_endgrent(void) {
    DEBUG("Closing %s for enumeration\n", OSLOGIN_GROUP_CACHE_PATH);
    if (g_file_thread) {
        fclose(g_file_thread);
        g_file_thread = NULL;
    }
    return NSS_STATUS_SUCCESS;
}

// _nss_cache_oslogin_getgrent_r()
// Called by NSS to get the next entry from the group file, using the
// thread-local file pointer.
enum nss_status
_nss_cache_oslogin_getgrent_r(struct group *result, char *buffer,
                               size_t buflen, int *errnop) {
    if (g_file_thread == NULL) {
        if (_nss_cache_oslogin_setgrent(0) != NSS_STATUS_SUCCESS) {
            *errnop = errno;
            return NSS_STATUS_UNAVAIL;
        }
    }

    struct group *grp = NULL;
    if (fgetgrent_r(g_file_thread, result, buffer, buflen, &grp) == 0 && grp != NULL) {
        DEBUG("Returning group %s (%u)\n", result->gr_name, result->gr_gid);
        return NSS_STATUS_SUCCESS;
    }

    *errnop = errno;
    if (*errnop == ENOENT) {
        *errnop = 0;
    }
    return _nss_cache_oslogin_ent_bad_return_code(*errnop);
}

// _nss_cache_oslogin_getgrgid_r()
// Stateless lookup for a group by GID.
enum nss_status
_nss_cache_oslogin_getgrgid_r(gid_t gid, struct group *result,
                               char *buffer, size_t buflen, int *errnop) {
    // First, check for user-private-group (UPG). This calls the stateless
    // _nss_cache_oslogin_getpwuid_r, so it won't cause side effects.
    struct passwd user;
    size_t userbuflen = 1024;
    char userbuf[userbuflen];
    if (_nss_cache_oslogin_getpwuid_r(gid, &user, userbuf, userbuflen, errnop) == NSS_STATUS_SUCCESS && user.pw_gid == user.pw_uid) {
        result->gr_gid = user.pw_gid;

        // store "x" for password.
        char* string = buffer;
        strncpy(string, "x", 2);
        result->gr_passwd = string;

        // store name.
        string = (char *)((size_t) string + 2);
        size_t name_len = strlen(user.pw_name)+1;
        strncpy(string, user.pw_name, name_len);
        result->gr_name = string;

        // member array starts past strings.
        char **strarray = (char **)((size_t) string + name_len);
        strarray[0] = string;
        strarray[1] = NULL;
        result->gr_mem = strarray;
        return NSS_STATUS_SUCCESS;
    }

    // If not a UPG, perform a stateless lookup in the group cache file.
    FILE *file = fopen(OSLOGIN_GROUP_CACHE_PATH, "re");
    if (file == NULL) {
        *errnop = errno;
        return NSS_STATUS_UNAVAIL;
    }

    enum nss_status ret = NSS_STATUS_NOTFOUND;
    *errnop = 0;
    struct group *grp = NULL;

    while (fgetgrent_r(file, result, buffer, buflen, &grp) == 0 && grp != NULL) {
        if (grp->gr_gid == gid) {
            ret = NSS_STATUS_SUCCESS;
            break;
        }
    }

    if (grp == NULL && errno != 0) {
        *errnop = errno;
        ret = _nss_cache_oslogin_ent_bad_return_code(*errnop);
    }

    fclose(file);
    return ret;
}

// _nss_cache_oslogin_getgrnam_r()
// Stateless lookup for a group by name.
enum nss_status
_nss_cache_oslogin_getgrnam_r(const char *name, struct group *result,
                               char *buffer, size_t buflen, int *errnop) {
    // First, check for user-private-group (UPG).
    struct passwd user;
    size_t userbuflen = 1024;
    char userbuf[userbuflen];
    if (_nss_cache_oslogin_getpwnam_r(name, &user, userbuf, userbuflen, errnop) == NSS_STATUS_SUCCESS && user.pw_gid == user.pw_uid) {
        result->gr_gid = user.pw_gid;

        // store "x" for password.
        char* string = buffer;
        strncpy(string, "x", 2);
        result->gr_passwd = string;

        // store name.
        string = (char *)((size_t) string + 2);
        size_t name_len = strlen(user.pw_name)+1;
        strncpy(string, user.pw_name, name_len);
        result->gr_name = string;

        // member array starts past strings.
        char **strarray = (char **)((size_t) string + name_len);
        strarray[0] = string;
        strarray[1] = NULL;
        result->gr_mem = strarray;
        return NSS_STATUS_SUCCESS;
    }

    // If not a UPG, perform a stateless lookup in the group cache file.
    FILE *file = fopen(OSLOGIN_GROUP_CACHE_PATH, "re");
    if (file == NULL) {
        *errnop = errno;
        return NSS_STATUS_UNAVAIL;
    }

    enum nss_status ret = NSS_STATUS_NOTFOUND;
    *errnop = 0;
    struct group *grp = NULL;

    while (fgetgrent_r(file, result, buffer, buflen, &grp) == 0 && grp != NULL) {
        if (strcmp(grp->gr_name, name) == 0) {
            ret = NSS_STATUS_SUCCESS;
            break;
        }
    }

    if (grp == NULL && errno != 0) {
        *errnop = errno;
        ret = _nss_cache_oslogin_ent_bad_return_code(*errnop);
    }

    fclose(file);
    return ret;
}


//
// NSS method registration
//

NSS_METHOD_PROTOTYPE(__nss_compat_getpwnam_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getpwuid_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getpwent_r);
NSS_METHOD_PROTOTYPE(__nss_compat_setpwent);
NSS_METHOD_PROTOTYPE(__nss_compat_endpwent);

NSS_METHOD_PROTOTYPE(__nss_compat_getgrnam_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getgrgid_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getgrent_r);
NSS_METHOD_PROTOTYPE(__nss_compat_setgrent);
NSS_METHOD_PROTOTYPE(__nss_compat_endgrent);

DECLARE_NSS_METHOD_TABLE(methods,
    { NSDB_PASSWD, "getpwnam_r", __nss_compat_getpwnam_r, (void*)_nss_cache_oslogin_getpwnam_r },
    { NSDB_PASSWD, "getpwuid_r", __nss_compat_getpwuid_r, (void*)_nss_cache_oslogin_getpwuid_r },
    { NSDB_PASSWD, "getpwent_r", __nss_compat_getpwent_r, (void*)_nss_cache_oslogin_getpwent_r },
    { NSDB_PASSWD, "endpwent",   __nss_compat_endpwent,   (void*)_nss_cache_oslogin_endpwent   },
    { NSDB_PASSWD, "setpwent",   __nss_compat_setpwent,   (void*)_nss_cache_oslogin_setpwent   },

    { NSDB_GROUP,  "getgrnam_r", __nss_compat_getgrnam_r, (void*)_nss_cache_oslogin_getgrnam_r },
    { NSDB_GROUP,  "getgrgid_r", __nss_compat_getgrgid_r, (void*)_nss_cache_oslogin_getgrgid_r },
    { NSDB_GROUP,  "getgrent_r", __nss_compat_getgrent_r, (void*)_nss_cache_oslogin_getgrent_r },
    { NSDB_GROUP,  "endgrent",   __nss_compat_endgrent,   (void*)_nss_cache_oslogin_endgrent   },
    { NSDB_GROUP,  "setgrent",   __nss_compat_setgrent,   (void*)_nss_cache_oslogin_setgrent   }
)

NSS_REGISTER_METHODS(methods)
