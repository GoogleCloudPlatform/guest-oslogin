SHELL = /bin/sh
TOPDIR = $(realpath ..)

CPPFLAGS = -Iinclude -I/usr/include/json-c -I$(TOPDIR)/third_party/include
FLAGS = -fPIC -Wall -g
CFLAGS = $(FLAGS) -Wstrict-prototypes
CXXFLAGS = $(FLAGS)

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

NSS_OSLOGIN_SONAME       = libnss_oslogin.so.2
NSS_CACHE_OSLOGIN_SONAME = libnss_cache_oslogin.so.2

NSS_OSLOGIN              = libnss_oslogin-$(VERSION).so
NSS_CACHE_OSLOGIN        = libnss_cache_oslogin-$(VERSION).so

PAM_BYOID                = pam_oslogin_byoid.so
PAM_LOGIN                = pam_oslogin_login.so
PAM_ADMIN                = pam_oslogin_admin.so

BINARIES = google_oslogin_nss_cache google_authorized_keys google_authorized_keys_sk

.PHONY: all clean install
.DEFAULT_GOAL := all

all: $(NSS_OSLOGIN) $(NSS_CACHE_OSLOGIN) $(PAM_LOGIN) $(PAM_BYOID) $(PAM_ADMIN) $(BINARIES)

clean:
	rm -f $(BINARIES)
	find . -type f \( -iname '*.o' -o -iname '*.so' \) -delete

# NSS modules.

$(NSS_OSLOGIN): SONAME = $(NSS_OSLOGIN_SONAME)
$(NSS_OSLOGIN): nss/nss_oslogin.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(NSS_CACHE_OSLOGIN): SONAME = $(NSS_CACHE_OSLOGIN_SONAME)
$(NSS_CACHE_OSLOGIN): nss/nss_cache_oslogin.o nss/compat/getpwent_r.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# PAM modules

$(PAM_BYOID): pam/pam_oslogin_byoid.o pam/oslogin_sshca.o oslogin_utils.o include/oslogin_sshca.h
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -shared $^ -o $@ $(PAMLIBS)

$(PAM_LOGIN): pam/pam_oslogin_login.o pam/oslogin_sshca.o oslogin_utils.o include/oslogin_sshca.h
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -shared $^ -o $@ $(PAMLIBS)

$(PAM_ADMIN): pam/pam_oslogin_admin.o pam/oslogin_sshca.o oslogin_utils.o include/oslogin_sshca.h
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -shared $^ -o $@ $(PAMLIBS)

# Utilities.

google_authorized_keys: authorized_keys/authorized_keys.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

google_authorized_keys_sk: authorized_keys/authorized_keys_sk.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

google_oslogin_nss_cache: cache_refresh/cache_refresh.o oslogin_utils.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDLIBS)

install: all
	# Make dirs
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(PAMDIR)
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(MANDIR)/man8
	# NSS modules
	install -m 0644 -t $(DESTDIR)$(LIBDIR) $(NSS_OSLOGIN) $(NSS_CACHE_OSLOGIN)
	ln -sf $(NSS_OSLOGIN)         $(DESTDIR)$(LIBDIR)/$(NSS_OSLOGIN_SONAME)
	ln -sf $(NSS_CACHE_OSLOGIN)   $(DESTDIR)$(LIBDIR)/$(NSS_CACHE_OSLOGIN_SONAME)
	# PAM modules
	install -m 0644 -t $(DESTDIR)$(PAMDIR) $(PAM_ADMIN) $(PAM_LOGIN)
	# Binaries
	install -m 0755 -t $(DESTDIR)$(BINDIR) $(BINARIES)
	# Manpages
	install -m 0644 -t $(DESTDIR)$(MANDIR)/man8 $(TOPDIR)/man/nss-oslogin.8 $(TOPDIR)/man/nss-cache-oslogin.8
	gzip -9f $(DESTDIR)$(MANDIR)/man8/nss-oslogin.8
	gzip -9f $(DESTDIR)$(MANDIR)/man8/nss-cache-oslogin.8
	ln -sf nss-oslogin.8.gz       $(DESTDIR)$(MANDIR)/man8/$(NSS_OSLOGIN_SONAME).8.gz
	ln -sf nss-cache-oslogin.8.gz $(DESTDIR)$(MANDIR)/man8/$(NSS_CACHE_OSLOGIN_SONAME).8.gz
ifdef INSTALL_SELINUX
	# SELinux policy package
	install -d $(DESTDIR)/usr/share/selinux/packages
	install -m 0644 -t $(DESTDIR)/usr/share/selinux/packages $(TOPDIR)/selinux/oslogin.pp
endif
ifdef INSTALL_CRON
	# Cache refresh cron
	install -d $(DESTDIR)$(CRONDIR)
	install -m 0644 $(TOPDIR)/cron.d $(DESTDIR)$(CRONDIR)/google-compute-engine-oslogin
else
	# Cache refresh systemd timer
	install -d $(DESTDIR)$(SYSTEMDDIR)
	install -m 0644 -t $(DESTDIR)$(SYSTEMDDIR) $(TOPDIR)/google-oslogin-cache.timer $(TOPDIR)/google-oslogin-cache.service
	install -d $(DESTDIR)$(PRESETDIR)
	install -m 0644 -t $(DESTDIR)$(PRESETDIR) $(TOPDIR)/90-google-compute-engine-oslogin.preset
endif
