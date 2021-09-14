/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once
#include "HardwareAuthenticatorType.h"
#include "Timestamp.h"
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
class HardwareAuthToken {
  public:
    int64_t challenge = 0L;
    int64_t userId = 0L;
    int64_t authenticatorId = 0L;
    HardwareAuthenticatorType authenticatorType = HardwareAuthenticatorType::NONE;
    Timestamp timestamp;
    std::vector<uint8_t> mac;

    inline std::string toString() const {
        std::ostringstream os;
        os << "HardwareAuthToken{";
        os << "}";
        return os.str();
    }
};
}  // namespace keymaster::javacard::test
