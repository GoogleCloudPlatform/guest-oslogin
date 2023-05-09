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

#ifndef TRUSTED_CA_KEYS_H_
#define TRUSTED_CA_KEYS_H_

#include <vector>
#include <fstream>
#include <string>

using std::string;
using std::vector;
using std::ofstream;

// A default API endpoint
const char *mds_url_def = "http://169.254.169.254/computeMetadata/v1/oslogin/certificates";
// A default file with CA keys
const char *trusted_keys_file_def = "/etc/ssh/trustedca.pub";
// A suffix for the temporary file
const char *tmp_suff = ".temp";

// Creates a temporary file, sets an owner and permissions.
// It is used for storing fetched keys and then moved to the destination
// file at very end.
// Returns:
//    0 if it was opened and ready to use
//   -1 if couldn't open a file
//   -2 if couldn't set an owner
//   -3 if couldn't set permissions
//
int
CreateTmpKeysFile(ofstream& trusted_keys_tmp_file,
                  const string& trusted_keys_tmp_filename);

// Writes alredy fetched CA keys to the existing temporary file
void
WriteCAKeysTmpFile(ofstream& trusted_keys_tmp_file, const vector<string> ca_keys);

#endif  // TRUSTED_CA_KEYS_H_

