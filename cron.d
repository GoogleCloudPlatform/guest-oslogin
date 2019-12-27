# Run the NSS cache refresh script every six hours. The guest agent also invokes
# this script on start.

0 */6 * * * root /usr/bin/google_oslogin_nss_cache
