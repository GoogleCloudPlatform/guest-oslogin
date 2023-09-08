# Run the NSS cache refresh script every six hours. The guest agent also invokes
# this script on start.
# Run Trusted CA SSH key sync every 5 min

0 */6 * * * root /usr/bin/google_oslogin_nss_cache
*/5 * * * * root /usr/bin/google_trusted_ca_keys
