#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
enum class HardwareAuthenticatorType : int32_t {
  NONE = 0,
  PASSWORD = 1,
  FINGERPRINT = 2,
  ANY = -1,
};

static inline std::string toString(HardwareAuthenticatorType val) {
  switch(val) {
  case HardwareAuthenticatorType::NONE:
    return "NONE";
  case HardwareAuthenticatorType::PASSWORD:
    return "PASSWORD";
  case HardwareAuthenticatorType::FINGERPRINT:
    return "FINGERPRINT";
  case HardwareAuthenticatorType::ANY:
    return "ANY";
  default:
    return std::to_string(static_cast<int32_t>(val));
  }
}
}  // namespace keymaster::javacard::test
