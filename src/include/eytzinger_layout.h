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

#ifndef OSLOGIN_EYTZINGER_LAYOUT_H
#define OSLOGIN_EYTZINGER_LAYOUT_H

#include <cstddef>
#include <functional>
#include <vector>

// Function to convert a sorted vector to Eytzinger layout.
// The input vector must be sorted.
// Returns a new vector with elements arranged in Eytzinger layout.
template <typename T>
std::vector<T> to_eytzinger_layout(const std::vector<T>& sorted_input) {
  if (sorted_input.empty()) {
    return {};
  }
  std::vector<T> output(sorted_input.size());

  std::function<void(size_t, size_t&)> eytzingerize =
    [&](size_t eytzinger_idx, size_t& sorted_idx) {
    if (eytzinger_idx - 1 < sorted_input.size()) {
      // Traverse Left Child (2 * eytzinger_idx)
      eytzingerize(2 * eytzinger_idx, sorted_idx);

      // Visit Node: Place the next element from sorted_input
      if (sorted_idx < sorted_input.size()) {
        output[eytzinger_idx - 1] = sorted_input[sorted_idx++];
      }

      // Traverse Right Child (2 * eytzinger_idx + 1)
      eytzingerize(2 * eytzinger_idx + 1, sorted_idx);
    }
  };

  size_t sorted_idx = 0;
  eytzingerize(1, sorted_idx);  // Start with Eytzinger index 1

  return output;
}

#endif  // OSLOGIN_EYTZINGER_LAYOUT_H
