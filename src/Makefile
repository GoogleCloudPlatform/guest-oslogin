SHELL = /bin/sh
TOPDIR = $(realpath ..)

CPPFLAGS += -I. -Iinclude -I/usr/include/json-c
FLAGS = -fPIC -Wall -g
CFLAGS += $(FLAGS) -Wstrict-prototypes
CXXFLAGS += $(FLAGS)

LDFLAGS = -shared -Wl,-soname,$(SONAME)
LDLIBS = -lcurl -ljson-c
PAMLIBS = -lpam $(LDLIBS)

# Paths which should be overrideable.

PREFIX = /usr
LIBDIR = $(PREFIX)/lib
BINDIR = $(PREFIX)/bin
PAMDIR = $(LIBDIR)/security
MANDIR = /usr/share/man
CRONDIR = /etc/cron.d
SYSTEMDDIR = /lib/systemd/system
PRESETDIR = /lib/systemd/system-preset
GOOGLEUSERSDIR = /var/google-users.d

DEST_LIBDIR = $(LIBDIR)
DEST_BINDIR = $(BINDIR)
DEST_PAMDIR = $(PAMDIR)
DEST_MANDIR = $(MANDIR)
DEST_SELINUX = /usr/share/selinux/packages
DEST_CRONDIR = $(CRONDIR)
DEST_SYSTEMDDIR = $(SYSTEMDDIR)
DEST_PRESETDIR = $(PRESETDIR)
DEST_GOOGLEUSERSDIR = $(GOOGLEUSERSDIR)

ifneq ($(DESTDIR),)
DEST_LIBDIR = $(DESTDIR)/$(LIBDIR)
DEST_BINDIR = $(DESTDIR)/$(BINDIR)
DEST_PAMDIR = $(DESTDIR)/$(PAMDIR)
DEST_MANDIR = $(DESTDIR)/$(MANDIR)
DEST_SELINUX = $(DESTDIR)/usr/share/selinux/packages
DEST_CRONDIR = $(DESTDIR)/$(CRONDIR)
DEST_SYSTEMDDIR = $(DESTDIR)/$(SYSTEMDDIR)
DEST_PRESETDIR = $(DESTDIR)/$(PRESETDIR)
DEST_GOOGLEUSERSDIR = $(DESTDIR)/$(GOOGLEUSERSDIR)
endif

NSS_OSLOGIN_SONAME       = libnss_oslogin.so.2
NSS_CACHE_OSLOGIN_SONAME = libnss_cache_oslogin.so.2

NSS_OSLOGIN              = libnss_oslogin-$(VERSION).so
NSS_CACHE_OSLOGIN        = libnss_cache_oslogin-$(VERSION).so

PAM_ADMIN                = pam_oslogin_admin.so
PAM_LOGIN                = pam_oslogin_login.so

BINARIES = google_oslogin_nss_cache google_authorized_keys google_authorized_keys_sk google_authorized_principals

.PHONY: all clean install
.DEFAULT_GOAL := all

all: $(NSS_OSLOGIN) $(NSS_CACHE_OSLOGIN) $(PAM_LOGIN) $(PAM_ADMIN) $(BINARIES)

clean:
	rm -f $(BINARIES)
	find . -type f \( -iname '*.o' -o -iname '*.so' \) -delete

# NSS modules.

$(NSS_OSLOGIN): SONAME = $(NSS_OSLOGIN_SONAME)
$(NSS_OSLOGIN): nss/nss_oslogin.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(NSS_CACHE_OSLOGIN): SONAME = $(NSS_CACHE_OSLOGIN_SONAME)
$(NSS_CACHE_OSLOGIN): nss/nss_cache_oslogin.o nss/compat/getpwent_r.o oslogin_utils.o nss/oslogin_passwd_cache_reader.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# PAM modules

$(PAM_LOGIN): pam/pam_oslogin_login.o oslogin_sshca.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -shared $^ -o $@ $(PAMLIBS)

$(PAM_ADMIN): pam/pam_oslogin_admin.o oslogin_sshca.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -shared $^ -o $@ $(PAMLIBS)

# Utilities.

google_authorized_principals: authorized_principals/authorized_principals.o oslogin_utils.o oslogin_sshca.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

google_authorized_keys: authorized_keys/authorized_keys.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

google_authorized_keys_sk: authorized_keys/authorized_keys_sk.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

google_oslogin_nss_cache: cache_refresh/cache_refresh.o cache_refresh/oslogin_passwd_cache_writer.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

install: all
	# Make dirs
	install -d $(DEST_LIBDIR)
	install -d $(DEST_PAMDIR)
	install -d $(DEST_BINDIR)
	install -d $(DEST_MANDIR)/man8
	# NSS modules
	install -m 0644 -t $(DEST_LIBDIR) $(NSS_OSLOGIN) $(NSS_CACHE_OSLOGIN)
	ln -sf $(NSS_OSLOGIN)         $(DEST_LIBDIR)/$(NSS_OSLOGIN_SONAME)
	ln -sf $(NSS_CACHE_OSLOGIN)   $(DEST_LIBDIR)/$(NSS_CACHE_OSLOGIN_SONAME)
	# PAM modules
	install -m 0644 -t $(DEST_PAMDIR) $(PAM_LOGIN) $(PAM_ADMIN)
	# Binaries
	install -m 0755 -t $(DEST_BINDIR) $(BINARIES)
	# Manpages
	install -m 0644 -t $(DEST_MANDIR)/man8 $(TOPDIR)/man/nss-oslogin.8 $(TOPDIR)/man/nss-cache-oslogin.8
	gzip -9f $(DEST_MANDIR)/man8/nss-oslogin.8
	gzip -9f $(DEST_MANDIR)/man8/nss-cache-oslogin.8
	ln -sf nss-oslogin.8.gz       $(DEST_MANDIR)/man8/$(NSS_OSLOGIN_SONAME).8.gz
	ln -sf nss-cache-oslogin.8.gz $(DEST_MANDIR)/man8/$(NSS_CACHE_OSLOGIN_SONAME).8.gz
ifdef INSTALL_SELINUX
	# SELinux policy package
	install -d $(DEST_SELINUX)
	install -m 0644 -t $(DEST_SELINUX) $(TOPDIR)/selinux/oslogin.pp
endif
ifdef INSTALL_CRON
	# Cache refresh cron
	install -d $(DEST_CRONDIR)
	install -m 0644 $(TOPDIR)/cron.d $(DEST_CRONDIR)/google-compute-engine-oslogin
else
	# Cache refresh systemd timer
	install -d $(DEST_SYSTEMDDIR)
	install -m 0644 -t $(DEST_SYSTEMDDIR) $(TOPDIR)/google-oslogin-cache.timer $(TOPDIR)/google-oslogin-cache.service
	install -d $(DEST_PRESETDIR)
	install -m 0644 -t $(DEST_PRESETDIR) $(TOPDIR)/90-google-compute-engine-oslogin.preset
endif
	# README file in google-users.d
	install -m 0640 -d $(DEST_GOOGLEUSERSDIR)
	install -m 0644 -T $(TOPDIR)/google-users-d-README $(DEST_GOOGLEUSERSDIR)/README

