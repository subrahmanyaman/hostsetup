#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <sstream>
#include <vector>
#include "KeyParameter.h"
#include "SecurityLevel.h"

namespace keymaster::javacard::test {
class KeyCharacteristics {
public:

  SecurityLevel securityLevel = SecurityLevel::SOFTWARE;
  std::vector<KeyParameter> authorizations;

  inline bool operator!=(const KeyCharacteristics& rhs) const {
    return std::tie(securityLevel, authorizations) != std::tie(rhs.securityLevel, rhs.authorizations);
  }
  inline bool operator<(const KeyCharacteristics& rhs) const {
    return std::tie(securityLevel, authorizations) < std::tie(rhs.securityLevel, rhs.authorizations);
  }
  inline bool operator<=(const KeyCharacteristics& rhs) const {
    return std::tie(securityLevel, authorizations) <= std::tie(rhs.securityLevel, rhs.authorizations);
  }
  inline bool operator==(const KeyCharacteristics& rhs) const {
    return std::tie(securityLevel, authorizations) == std::tie(rhs.securityLevel, rhs.authorizations);
  }
  inline bool operator>(const KeyCharacteristics& rhs) const {
    return std::tie(securityLevel, authorizations) > std::tie(rhs.securityLevel, rhs.authorizations);
  }
  inline bool operator>=(const KeyCharacteristics& rhs) const {
    return std::tie(securityLevel, authorizations) >= std::tie(rhs.securityLevel, rhs.authorizations);
  }

  inline std::string toString() const {
    std::ostringstream os;
    os << "KeyCharacteristics{";
    os << "}";
    return os.str();
  }
};
}  // namespace keymaster::javacard::test

