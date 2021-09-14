#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
enum class SecurityLevel : int32_t {
    SOFTWARE = 0,
    TRUSTED_ENVIRONMENT = 1,
    STRONGBOX = 2,
    KEYSTORE = 100,
};

static inline std::string toString(SecurityLevel val) {
    switch (val) {
    case SecurityLevel::SOFTWARE:
        return "SOFTWARE";
    case SecurityLevel::TRUSTED_ENVIRONMENT:
        return "TRUSTED_ENVIRONMENT";
    case SecurityLevel::STRONGBOX:
        return "STRONGBOX";
    case SecurityLevel::KEYSTORE:
        return "KEYSTORE";
    default:
        return std::to_string(static_cast<int32_t>(val));
    }
}
}  // namespace keymaster::javacard::test
