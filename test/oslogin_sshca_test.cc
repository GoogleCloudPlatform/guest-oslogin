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

#include <errno.h>
#include <gtest/gtest.h>
#include <oslogin_sshca.h>
#include <stdio.h>
#include <stdlib.h>

using std::string;
using std::vector;

namespace oslogin_utils {

#define VALID_ECDSA_SINGLE_EXT "ecdsa-sha2-nistp256-cert-v01@openssh.com " \
  "AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg1yMhf" \
  "NVBe4etWEQNDmtxhsAD+YAb7fl/Bn0Z+GGEE9EAAAAIbmlzdHAyNTYAAABBBJ+nM2cR4B" \
  "FHbmokUIScpTaSkx/F1QS2KfIx6z4wcpUmjzKtbP0KFw12mMUiNHzlNBD0B2RnX54uN+k" \
  "bjYGUdSAAAAAAAAAAAAAAAAEAAAAScGFudGhlb24uc2l0YXIubWlnAAAAFgAAABJwYW50" \
  "aGVvbi5zaXRhci5taWcAAAAAAAAAAP//////////AAAAAAAAAEMAAAA7ZmluZ2VycHJpb" \
  "nRAZ29vZ2xlLmNvbT1iODZkYjRjYS0wOWZkLTQyOWUtYjEyMS1hMTI3OTk2MTQwMzIAAA" \
  "AAAAAAAAAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAKgQiEGiszewwIeTPZv1/wwQF7K" \
  "JeStkko6w7tcUXRUFWc1ajBUXjEQAxv64JSC+RvlFn7NTVxwzHb+lnbU9+74xfLKB9pqb" \
  "XwiO8HNr4OhLdqfn6x8alfUwsezJzhdBs86o9B9YTFwX2UMJ0c3rZ/0Do6V3WlckMFiPh" \
  "ZiXyiW3pYve+7kj9EZ/WJMAdxTnLPNF03azy3+siyVOWL2zkL8DVscpVVQ51ln15mwvI4" \
  "/e0BVQbP0rtfGIjVOaUM4PyLAfTwg/GPpXroNefvRaxF1scXIjxVQTgm7EauWUyl0i4A1" \
  "sQVEoXWyxQsgdGd6+BTZ3khJCAVSnLTeIhvP9utGJhSLvuJFZu1S1oA1s1/pvpDE9Nfc1" \
  "QT14pWKGUU05Z8yPuBSwbbPqQZvSBhCsVNC5wN6AEkiIsKRJkcSXZIqGQpY9CUAJi9GxS" \
  "R7ATiSy9GAJypHkHNDmJeBEfxYk7Z7jWBZ39HikmAaUfPYzpfjc0nPxYMkMKKy5wnftia" \
  "pVxwAAAZQAAAAMcnNhLXNoYTItNTEyAAABgA4z6rSDNPKG9ae/C11q0U1CsPscK8tXFuK" \
  "surZNXnfAbNwPp8/7x5pamgq5119PnAacll29U9+L+dYwmU8NsJgd1nnQPXh2hLdGs828" \
  "hMOxSgwj35YSzToSulwmOxG7uOYI056WBc3ZZtcxBqvHThLAo6J2TnURicNMvID42ofqQ" \
  "H2Wgozg1AOyHwCDdkrG304NoSfx76tIf/RjLu7yedhhu1x0hbz4DsLLKlm5vVI8jQvLB7" \
  "iz37LMdvftX+Zqnf2EWDT7GspchbrCStH15GXaMCXwyObbDmKkYLz77XckBAQLjm0C6f2" \
  "+f8UxtWzZDvqVFr/iIpivaRUhpGMYNED43XAKR/8uAMKA9d7mB8lD9wMBmRxbG4qDTM4q" \
  "7Q539h7IPMoTRN82VL0v1KPVW8uWqqSjVFdrr2DshitTALMwXpf4VIxw/XuOV5ALNTCan" \
  "bcetrgglFiujUFlIdxkHMmsIxHM88wEnJAlETd7zl9WR/FgQYn3y2dZz9VKoheJdg== "  \
  "pantheon.sitar.mig"                                                    \

#define INVALID_ECDSA_NO_FP "ecdsa-sha2-nistp256-cert-v01@openssh.com A" \
  "AAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgxlbtL" \
  "/mjYXEgsXjl7GZgpvIFncxbfmjPYVewm1sdXo4AAAAIbmlzdHAyNTYAAABBBMYdGLr6M" \
  "102qgBeJ3CanDi0WV1vGif2jMMv1ldtN0+wbDztYdtUu8iop/tN46wFVbfmSzyx/R2YL" \
  "bvQ+z2k/sYAAAAAAAAAAAAAAAEAAAAWZmluZ2VycHJpbnRAZ29vZ2xlLmNvbQAAABoAA" \
  "AAWZmluZ2VycHJpbnRAZ29vZ2xlLmNvbQAAAABk0UUMAAAAAGaxJ2gAAAAAAAAAAAAAA" \
  "AAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPoCTDKl0" \
  "jZG3V2P14+PDbYrD0sDBsKwYaZEn85tM6mmGEY1yHg/VI76O27xTqE56PJECph1eKmo4" \
  "YA/ch8wwewAAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIQCN6KRgSVKYH" \
  "pM3dlil8jDXlpL4U1JSmP3MeHX0OKcpHgAAACAYiWa3KrreEzN+VrnuhwStH70bvH9Qm" \
  "6Va6a0IcMrMkA== fingerprint@google.com"                               \

#define INVALID_ECDSA_NON_CERT "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI" \
  "tbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMYdGLr6M102qgBeJ3CanDi0WV1vGif2jMM" \
  "v1ldtN0+wbDztYdtUu8iop/tN46wFVbfmSzyx/R2YLbvQ+z2k/sY= "               \
  "fingerprint@google.com"                                               \

#define VALID_RSA_SINGLE_EXT "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc" \
  "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" \
  "GqmJpNjwsqExxW5E= fingerprint@google.com"                              \

#define INVALID_RSA_NO_FP "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2Et" \
  "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 "     \
  "fingerprint@google.com"                                                \

#define INVALID_RSA_NON_CERT "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCU/m" \
  "ydd9mSwlSDv4T3OiL5IHrvSuXpWFvCEDmVyLxBHz1FCwjnk3G5xSt9nGtUyL0KpGt0dyv" \
  "LU07JGB33cbVnVe1z3373FNKxF8LdwDTEZG6xijXuOi4xfk47arlpk9Pw14qcnVu9on4R" \
  "m4cSmm5PkyIwTfJsKvOl8oOgZ0HZG7pzYEt+9wUoeGzUE0rsAreNFVB7ZBqHp2ZtdIe5d" \
  "dbarKAl1JKZuz8EbUmdjBYXsMYLHd0gUd+rvHyaw7p3iJyESaJcqUOQHrecpkLqWiN+TU" \
  "NZPchE/T19LSP/fQbPCGmqc+mC6YodSEbLkO6JmOaW+knTEc9D6xdozx6Oa4vR "       \
  "fingerprint@google.com"                                                \

#define VALID_DSA_SINGLE_EXT "ssh-dss-cert-v01@openssh.com AAAAHHNzaC1kc" \
  "3MtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgH400e9SzsvaN8OkKvH26sXEJtU/BVc2IBG" \
  "fdZDHk508AAACBAO9UdOmq7Z0qy86mwsDf07TmXQe7X0TLKbyFSsd2b+jTCzpXy9rBhgg" \
  "oJlzYzxSQgtR4JaSTauZMiQQViN3cKvHuGfAXIOIMtMHVupNy6WSkcixGrvw6Y0Yr90+e" \
  "8PXcFw6jwQbFZX4v9zlUuIl067rCrxp1jnhBjxvBZEmpR/ezAAAAFQCO10V2wYXJ7cSo4" \
  "eEgHB1BnOxbzwAAAIEAzbdt5bgzV164ljY6dimHUUnKUnYEq7VY3gJZSN3YGwMHnIYw94" \
  "gtNxkhP09SkPn+llAH/NTKq2beu9GizybqIc9Gtfh3AGqYLyWhePZumcUYYShMc7eNUfN" \
  "RDp1QtWnX/A/HvVsNEdqHW3R9cq5miEWgoUFHOHhLZtUOk1wbJe4AAACAITYKkJACQAoh" \
  "b9q1Ehxea8qoYaM2ctI3JCN59bbcgP1Tngaq2TcJOup0+AVN5P7ILQGh3s9xngdcQU9RJ" \
  "XlUh6yHpW0BwkAOAKjX7ASjx4rKOkN0PeT2KtyGWqLcnbFRSQGNQOs+vv3TIUofZosXKT" \
  "A2EtmjpKcIbfu3lF+J50gAAAAAAAAAAAAAAAEAAAAWZmluZ2VycHJpbnRAZ29vZ2xlLmN" \
  "vbQAAABoAAAAWZmluZ2VycHJpbnRAZ29vZ2xlLmNvbQAAAABk0SkoAAAAAGaxC5IAAAAA" \
  "AAAAQwAAADtmaW5nZXJwcmludEBnb29nbGUuY29tPWI4NmRiNGNhLTA5ZmQtNDI5ZS1iM" \
  "TIxLWExMjc5OTYxNDAzMgAAAAAAAAAAAAABsgAAAAdzc2gtZHNzAAAAgQC1WfAI4qlV3J" \
  "jY+tsHhQEVJgMVPzrNa94pvSDRc9FYexYHaky6e0zroP8LmxTEZyOzfT9H22lqmIPRHXp" \
  "dEB5ge7FAO7/QsavsAUQHnpiyaqng4ojgPTQJzY0tuYUkV9a265gZJpqdY0wNLcSJtDFk" \
  "WtixpTSswF1gGs5maq5ljQAAABUAlYIrD8mImqdRNg7FizxOscWV8WUAAACBAJE9UuRok" \
  "fqK1ZodxfX0Me1NgS+4rpH9iWqHudpQiR134OUT3w29dtTDKdDjesuOyEDGi17Z5Honsv" \
  "yktNVzel+F8q6/24NI4VSBnRXi8TkXvK6BjRFJsnVJRMiF8zErd3ihWDmsEXcMJ0X/uQw" \
  "tBKREhGri3xz1bVVH+Iwb8F5SAAAAgFtqHHk0TP8wLmggYh+i9FDhN+99yt7FxDAGg4di" \
  "JDkpmo8MUaXmxibghK0c15Tta9hoOUqtArpYdBm0WyfEM/5Us2qVVcJp4Cjrw9OJ3lEgj" \
  "+OSizEVlMEujCFT/j032c5Y4O3ScCEUDrFjlutMtlUfvPaDGX7yH0mYONAb6p2FAAAANw" \
  "AAAAdzc2gtZHNzAAAAKH5faM5YTlMn+h2cf99PJ8rjvqQUJoh5yi3a4pkGcr5MJs53Wfi" \
  "DPaA= fingerprint@google.com"                                          \

#define INVALID_DSA_NO_FP "ssh-dss-cert-v01@openssh.com AAAAHHNzaC1kc3Mt" \
  "Y2VydC12MDFAb3BlbnNzaC5jb20AAAAgGrlYnOqQxs/zzfWRcrM7DHrFy653/x7rtOghw" \
  "R/f3HIAAACBALzWA8yWLownZsO4Tuc4DF6EplCJ1SBSEqMYAEhzrnxjHkoOpJ3Ncs+Zn5" \
  "jdcnCamkm6KQ4keXkV0xwLthRgLxhUguc9xANV5k2Vft+axWr+cp+KNiGzDjblTUnWzQD" \
  "5Q/mBpiFKL7EiZski3swpJQs0kGQW2hxbjlr7I0EhM8e1AAAAFQDdVQaUxoK58jpTFdVi" \
  "gI3yzjtK3wAAAIB1Z8nZ4QEaqSLK5+Xm2LAbn32Do0nGtOkPCWYjZzlcfHt1Hb7gCIe5X" \
  "gqPZM3hYWuOisKsk2gxxeVyiX6VBuYpCbINduxw8h/7nMyOTFLr01Y282/eHq20XHPLD2" \
  "2hdY1l44de8EhYrcHRPM7twnFJU0X7og6QNdOnvMXQ+WclWwAAAIAmJmVahDp1Vu22M9t" \
  "7V4yRYP8Wh3ROletzPrY9kpgTR5QtfZ57QPxN3n2r61iLaPWR0cQ12x4LviBVTsFk87oE" \
  "9SAxzcDPwyzbSM3ATIzI6TauIVacVFoUdeAy2rjaLUGYcdD745oudXmyXq1VupLHaJC9k" \
  "ePm8hkeZyf/5F6XBwAAAAAAAAAAAAAAAQAAABZmaW5nZXJwcmludEBnb29nbGUuY29tAA" \
  "AAGgAAABZmaW5nZXJwcmludEBnb29nbGUuY29tAAAAAGTRQFwAAAAAZrEiogAAAAAAAAA" \
  "AAAAAAAAAAbEAAAAHc3NoLWRzcwAAAIEA4FZIvoI2syNIyZ34DibfH4Pm3Rf0iKHUIgLR" \
  "+izM/aP9jDAXRD/c2Tl2cnw4pVJdun2+ByBNkRHQJ+86dMVXhvpIPjoeK4dqJsEBsSj7L" \
  "ohXMJtdn5LyBpiiyZ4jq7uVeWGm1q7Lh6WeIuBVNLgwoE1/z5RtScGhbHBPb8q7RbcAAA" \
  "AVAOHoBqU7wxf09lWcarL6SaOAyWJ5AAAAgGLb9fIGSP50+sfKqxSohCU23B3SYCIf7QI" \
  "1Zjql9FeDY9AfvkzVaiJvA/eoZKwGhG5FbDtA9eyuCfiB5E6VqaShx3Mp3yCKPOaCznrv" \
  "LKJsqMKC7ReU2obugmMELRmbTdZdQCdvvNrVjqvW54aUIzF4zC9ZKeiKtG6MQ7VP/MrRA" \
  "AAAgGk5pXHfmjL8vDZIwtWhxm3gdN5TubyKgW1i/nIMDgLhLqLw4//NY86wkGj84MwniT" \
  "Gf2pB8lGzBPj+ByQIMABe/iMq9uRXLNUFta7PYQKi3UjCoCwv0p88advtwOXRyHu1THxr" \
  "JDMmmDirJnSYW8I7F9gY4UMldYwy9dyNqwfoQAAAANwAAAAdzc2gtZHNzAAAAKAnb/pHN" \
  "+YzrU7BOR7qnGs1qJqWhgFKXETMeHxPzpi4ny9tSNlI6c0g= "                     \
  "fingerprint@google.com"                                                \

#define INVALID_DSA_NON_CERT "ssh-dss AAAAB3NzaC1kc3MAAACBAO9UdOmq7Z0qy8" \
  "6mwsDf07TmXQe7X0TLKbyFSsd2b+jTCzpXy9rBhggoJlzYzxSQgtR4JaSTauZMiQQViN3" \
  "cKvHuGfAXIOIMtMHVupNy6WSkcixGrvw6Y0Yr90+e8PXcFw6jwQbFZX4v9zlUuIl067rC" \
  "rxp1jnhBjxvBZEmpR/ezAAAAFQCO10V2wYXJ7cSo4eEgHB1BnOxbzwAAAIEAzbdt5bgzV" \
  "164ljY6dimHUUnKUnYEq7VY3gJZSN3YGwMHnIYw94gtNxkhP09SkPn+llAH/NTKq2beu9" \
  "GizybqIc9Gtfh3AGqYLyWhePZumcUYYShMc7eNUfNRDp1QtWnX/A/HvVsNEdqHW3R9cq5" \
  "miEWgoUFHOHhLZtUOk1wbJe4AAACAITYKkJACQAohb9q1Ehxea8qoYaM2ctI3JCN59bbc" \
  "gP1Tngaq2TcJOup0+AVN5P7ILQGh3s9xngdcQU9RJXlUh6yHpW0BwkAOAKjX7ASjx4rKO" \
  "kN0PeT2KtyGWqLcnbFRSQGNQOs+vv3TIUofZosXKTA2EtmjpKcIbfu3lF+J50g= "      \
  "fingerprint@google.com"                                                \

#define VALID_ED25519_SINGLE_EXT "ssh-ed25519-cert-v01@openssh.com AAAAI" \
  "HNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIDaErnQWEw/jxPD0JUJsEk" \
  "CtENcE11Zl53QHbxbAgx22AAAAIHs6r2AekiTHmmoJMKxAKtKW4qcGq5Ku1+SJ1NLdZh0" \
  "1AAAAAAAAAAAAAAABAAAAFmZpbmdlcnByaW50QGdvb2dsZS5jb20AAAAaAAAAFmZpbmdl" \
  "cnByaW50QGdvb2dsZS5jb20AAAAAZNEqzAAAAABmsQ0IAAAAAAAAAEMAAAA7ZmluZ2Vyc" \
  "HJpbnRAZ29vZ2xlLmNvbT1iODZkYjRjYS0wOWZkLTQyOWUtYjEyMS1hMTI3OTk2MTQwMz" \
  "IAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgyxEJdP6tUhJY3J/4bgLpzyUojE9" \
  "6YKzE2t/RAx5l32kAAABTAAAAC3NzaC1lZDI1NTE5AAAAQNEBsSEvp5tVMbKUsjIZ0jEa" \
  "Yv0T0U/GZoCiLfVm3pcXV3RA8aze+y/pbjv+MOxjmAb4KbRH31/S34UALsyGwQM= fing" \
  "erprint@google.com"                                                    \

#define INVALID_ED25519_NO_FP "ssh-ed25519-cert-v01@openssh.com AAAAIHNz" \
  "aC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIDDgIXa9QLFY7RpSNnWDm3Saq" \
  "YZ5HGcpzHq9hdv64nqXAAAAIKfDRdZjpCb2YVsmhs286hQTH7JFctizNC0W7UQKfruSAA" \
  "AAAAAAAAAAAAABAAAAFmZpbmdlcnByaW50QGdvb2dsZS5jb20AAAAaAAAAFmZpbmdlcnB" \
  "yaW50QGdvb2dsZS5jb20AAAAAZNFCeAAAAABmsSTsAAAAAAAAAAAAAAAAAAAAMwAAAAtz" \
  "c2gtZWQyNTUxOQAAACBTEPiuWCgwX9JhFzMNLex4d9uRtdWfUg0OCAdH6nVbsAAAAFMAA" \
  "AALc3NoLWVkMjU1MTkAAABAt2CPRZos3Lna+44LwI6ON8rRktxAqz1S4nUf+IwrG83Wbv" \
  "nEvvZ2plHLTAU7GP2ZMedVKoXB9KXB2vNBVjt9Cg== fingerprint@google.com"     \

#define INVALID_ED25519_NON_CERT "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH" \
  "s6r2AekiTHmmoJMKxAKtKW4qcGq5Ku1+SJ1NLdZh01 fingerprint@google.com"     \

TEST(SSHCATests, TestValidSingleExtCert) {
  struct {
    const char *key;
  } *iter, tests[] = {
    {VALID_RSA_SINGLE_EXT},
    {VALID_DSA_SINGLE_EXT},
    {VALID_ECDSA_SINGLE_EXT},
    {VALID_ED25519_SINGLE_EXT},
    { NULL },
  };

  for (iter = tests; iter->key != NULL; iter++) {
    char *fingerprint = NULL;
    size_t len = sshca_get_byoid_fingerprint(NULL, iter->key, &fingerprint);
    ASSERT_GT(len, 0);
    ASSERT_STREQ(fingerprint, "b86db4ca-09fd-429e-b121-a12799614032");
    free(fingerprint);
  }
}

TEST(SSHCATests, TestInvalidNoFpCert) {
  struct {
    const char *key;
  } *iter, tests[] = {
    {INVALID_DSA_NO_FP},
    {INVALID_DSA_NON_CERT},
    {INVALID_ED25519_NO_FP},
    {INVALID_ED25519_NON_CERT},
    {INVALID_RSA_NO_FP},
    {INVALID_RSA_NON_CERT},
    {INVALID_ECDSA_NO_FP},
    {INVALID_ECDSA_NON_CERT},
    { NULL },
  };

  for (iter = tests; iter->key != NULL; iter++) {
    char *fingerprint = NULL;
    size_t len = sshca_get_byoid_fingerprint(NULL, iter->key, &fingerprint);
    ASSERT_EQ(len, 0);
    ASSERT_STREQ(fingerprint, NULL);
    free(fingerprint);
  }
}

}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
