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
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "oslogin_utils.h"
#include "trusted_ca_keys.h"

using std::cout;
using std::cerr;
using std::endl;
using std::flush;
using std::string;
using std::stringstream;
using std::vector;
using std::ofstream;

using oslogin_utils::HttpGet;
using oslogin_utils::ParseJsonToSuccess;
using oslogin_utils::ParseJsonToEmail;
using oslogin_utils::ParseJsonToSshKeys;
using oslogin_utils::UrlEncode;
using oslogin_utils::ParseJsonToCAKeys;

int
CreateTmpKeysFile(ofstream& trusted_keys_tmp_file,
                  const string& trusted_keys_tmp_filename) {

  trusted_keys_tmp_file.open(trusted_keys_tmp_filename.c_str());

  if (!trusted_keys_tmp_file.is_open()) {
      return -1;
  }

  if (chown(trusted_keys_tmp_filename.c_str(), 0, 0) != 0) {
      return -2;
  }
  if (chmod(trusted_keys_tmp_filename.c_str(),
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
      return -3;
  }
  return 0;
}

void
WriteCAKeysTmpFile(ofstream& trusted_keys_tmp_file, const vector<string> ca_keys) {

  for (size_t i = 0; i < ca_keys.size(); ++i) {
    trusted_keys_tmp_file << ca_keys[i] << endl;
  }
}

int
main(int argc, char* argv[]) {

  string trusted_keys_filename = trusted_keys_file_def;
  string mds_url = mds_url_def;
  char*  mds_url_env = NULL;

  if (argc >= 2) {
    if (strncmp(argv[1], "--help", 6) == 0 ||
        strncmp(argv[1], "-h", 2) == 0) {
      cout << "Usage: google_trusted_ca_keys [/path/to/trustedca.pub]\n\n"
           << "Environment:\n"
           << " - GOOGLE_OSLOGIN_MDS_URL=\"http://srv/path/to/certificates\"\n"
           << "Default values:\n"
           << " - CA keys file: /etc/ssh/trustedca.pub\n"
           << " - API endpoint: http://169.254.169.254/computeMetadata/v1/oslogin/certificates\n";

      return EXIT_SUCCESS;
    }
    trusted_keys_filename = argv[1];
  }

  if ( (mds_url_env = getenv("GOOGLE_OSLOGIN_MDS_URL")) != NULL) {
    mds_url = mds_url_env;
  }

  string trusted_keys_tmp_filename = trusted_keys_filename + tmp_suff;
  cout << "Updating the Trusted CA keys file... " << flush;

  ofstream trusted_keys_tmp_file;
  switch (CreateTmpKeysFile(trusted_keys_tmp_file, trusted_keys_tmp_filename)) {
      case -1: {
          stringstream err_msg;
          err_msg << "Failed!\n[ERROR] Can't open '"
                  << trusted_keys_tmp_filename;
          perror(err_msg.str().c_str());
          return EXIT_FAILURE;}
      case -2: {
          stringstream err_msg;
          err_msg << "Failed!\n[ERROR] Failed to set root:root file owner for "
                  << trusted_keys_tmp_filename;
          perror(err_msg.str().c_str());
          remove(trusted_keys_tmp_filename.c_str());
          return EXIT_FAILURE; }
      case -3: {
          stringstream err_msg;
          err_msg << "Failed!\n[ERROR] Failed to set 644 file permissions for "
                  << trusted_keys_tmp_filename;
          perror(err_msg.str().c_str());
          remove(trusted_keys_tmp_filename.c_str());
          return EXIT_FAILURE; }
      default:
          break;
  }

  string user_response;
  long http_code = 0;
  if (!HttpGet(string(mds_url.c_str()), &user_response, &http_code) ||
      user_response.empty() || http_code != 200) {

    cerr << "Failed!\n[ERROR] API call has failed. Metadata API endpoint '"
         << mds_url << "'\n";
    trusted_keys_tmp_file.close();
    remove(trusted_keys_tmp_filename.c_str());

    return EXIT_FAILURE;
  }

  vector<string> ca_keys;
  if (!ParseJsonToCAKeys(user_response, ca_keys)) {
    cerr << "Failed!\n[ERROR] Can't parse JSON response '"
         << user_response << "'\n";
    trusted_keys_tmp_file.close();
    remove(trusted_keys_tmp_filename.c_str());

    return EXIT_FAILURE;
  }

  WriteCAKeysTmpFile(trusted_keys_tmp_file, ca_keys);
  trusted_keys_tmp_file.close();

  if (rename(trusted_keys_tmp_filename.c_str(),
             trusted_keys_filename.c_str()) != 0) {

    stringstream err_msg;
    err_msg << "Failed!\n[ERROR] Failed moving " << trusted_keys_tmp_filename
            << " to " << trusted_keys_filename;
    perror(err_msg.str().c_str());
    remove(trusted_keys_tmp_filename.c_str());

    return EXIT_FAILURE;
  }

  cout << "Completed!\n";

  return EXIT_SUCCESS;
}
