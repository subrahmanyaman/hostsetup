#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <array>
namespace keymaster::javacard::test {
enum class KeyFormat : int32_t {
  X509 = 0,
  PKCS8 = 1,
  RAW = 3,
};

static inline std::string toString(KeyFormat val) {
  switch(val) {
  case KeyFormat::X509:
    return "X509";
  case KeyFormat::PKCS8:
    return "PKCS8";
  case KeyFormat::RAW:
    return "RAW";
  default:
    return std::to_string(static_cast<int32_t>(val));
  }
}
}  // namespace keymaster::javacard::test

