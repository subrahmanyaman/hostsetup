/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "key_param_output.h"

#include <iomanip>

#include "keymint_tags.h"

namespace keymaster::javacard::test {

using ::std::endl;
using ::std::ostream;

ostream& operator<<(ostream& os, const ::std::vector<KeyParameter>& set) {
    if (set.size() == 0) {
        os << "(Empty)" << endl;
    } else {
        os << "\n";
        for (const auto& elem : set) os << elem << endl;
    }
    return os;
}

ostream& operator<<(ostream& os, const KeyParameter& param) {
    return os << param.toString();
}

}  // namespace keymaster::javacard::test
