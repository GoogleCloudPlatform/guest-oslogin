// Copyright 2026 Google Inc. All Rights Reserved.
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

// Helpers for building raw SSH certificate blobs in tests. Plain C++ with no
// google3-only dependencies, so tests exported to GitHub can share it.

#ifndef OSLOGIN_TEST_SSHCA_CERT_BUILDER_H_
#define OSLOGIN_TEST_SSHCA_CERT_BUILDER_H_

#include <cstddef>
#include <cstdint>
#include <string>

namespace sshca_test {

// Internal linkage per TU; avoids needing C++17 inline variables for the
// GitHub Makefile build.
const char kFingerprint[] = "b86db4ca-09fd-429e-b121-a12799614032";

// Appends `v` in SSH wire format (big-endian uint32).
inline void AppendU32(std::string* out, uint32_t v) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    out->push_back(static_cast<char>((v >> shift) & 0xff));
  }
}

// Appends `v` in SSH wire format (big-endian uint64).
inline void AppendU64(std::string* out, uint64_t v) {
  AppendU32(out, static_cast<uint32_t>(v >> 32));
  AppendU32(out, static_cast<uint32_t>(v));
}

// Appends `s` as an SSH "string": a uint32 length followed by the bytes.
inline void AppendString(std::string* out, const std::string& s) {
  AppendU32(out, static_cast<uint32_t>(s.size()));
  out->append(s);
}

// Returns `s` encoded as an SSH "string".
inline std::string SshString(const std::string& s) {
  std::string out;
  AppendString(&out, s);
  return out;
}

// Standard (RFC 4648) base64 encoding with padding.
inline std::string Base64Encode(const std::string& in) {
  static const char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  size_t i = 0;
  for (; i + 2 < in.size(); i += 3) {
    uint32_t n = static_cast<uint8_t>(in[i]) << 16 |
                 static_cast<uint8_t>(in[i + 1]) << 8 |
                 static_cast<uint8_t>(in[i + 2]);
    out += kAlphabet[(n >> 18) & 63];
    out += kAlphabet[(n >> 12) & 63];
    out += kAlphabet[(n >> 6) & 63];
    out += kAlphabet[n & 63];
  }
  if (i + 1 == in.size()) {
    uint32_t n = static_cast<uint8_t>(in[i]) << 16;
    out += kAlphabet[(n >> 18) & 63];
    out += kAlphabet[(n >> 12) & 63];
    out += "==";
  } else if (i + 2 == in.size()) {
    uint32_t n = static_cast<uint8_t>(in[i]) << 16 |
                 static_cast<uint8_t>(in[i + 1]) << 8;
    out += kAlphabet[(n >> 18) & 63];
    out += kAlphabet[(n >> 12) & 63];
    out += kAlphabet[(n >> 6) & 63];
    out += '=';
  }
  return out;
}

// Raw (unencoded) ed25519 cert body up to and including the extensions field.
// The parser stops after the extensions field, so no signature is needed.
inline std::string BuildEd25519Cert(const std::string& principals_field,
                                    const std::string& extensions_field) {
  std::string cert;
  AppendString(&cert, "ssh-ed25519-cert-v01@openssh.com");
  AppendString(&cert, std::string(32, 'n'));  // nonce
  AppendString(&cert, std::string(32, 'k'));  // pk
  AppendU64(&cert, 1);                        // serial
  AppendU32(&cert, 1);                        // type (user)
  AppendString(&cert, "key-id");
  AppendString(&cert, principals_field);
  AppendU64(&cert, 0);      // valid after
  AppendU64(&cert, ~0ULL);  // valid before
  AppendString(&cert, "");  // critical options
  AppendString(&cert, extensions_field);
  return cert;
}

// An extensions field holding only the Google fingerprint extension, with
// empty data.
inline std::string DefaultExtensions() {
  return SshString(std::string("fingerprint@google.com=") + kFingerprint) +
         SshString("");
}

}  // namespace sshca_test

#endif  // OSLOGIN_TEST_SSHCA_CERT_BUILDER_H_
