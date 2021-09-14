#pragma once

#include "SecurityLevel.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
class KeyMintHardwareInfo {
  public:
    int32_t versionNumber = 0;
    SecurityLevel securityLevel = SecurityLevel::SOFTWARE;
    std::string keyMintName;
    std::string keyMintAuthorName;
    bool timestampTokenRequired = false;

    inline bool operator!=(const KeyMintHardwareInfo& rhs) const {
        return std::tie(versionNumber, securityLevel, keyMintName, keyMintAuthorName,
                        timestampTokenRequired) != std::tie(rhs.versionNumber, rhs.securityLevel,
                                                            rhs.keyMintName, rhs.keyMintAuthorName,
                                                            rhs.timestampTokenRequired);
    }
    inline bool operator<(const KeyMintHardwareInfo& rhs) const {
        return std::tie(versionNumber, securityLevel, keyMintName, keyMintAuthorName,
                        timestampTokenRequired) < std::tie(rhs.versionNumber, rhs.securityLevel,
                                                           rhs.keyMintName, rhs.keyMintAuthorName,
                                                           rhs.timestampTokenRequired);
    }
    inline bool operator<=(const KeyMintHardwareInfo& rhs) const {
        return std::tie(versionNumber, securityLevel, keyMintName, keyMintAuthorName,
                        timestampTokenRequired) <= std::tie(rhs.versionNumber, rhs.securityLevel,
                                                            rhs.keyMintName, rhs.keyMintAuthorName,
                                                            rhs.timestampTokenRequired);
    }
    inline bool operator==(const KeyMintHardwareInfo& rhs) const {
        return std::tie(versionNumber, securityLevel, keyMintName, keyMintAuthorName,
                        timestampTokenRequired) == std::tie(rhs.versionNumber, rhs.securityLevel,
                                                            rhs.keyMintName, rhs.keyMintAuthorName,
                                                            rhs.timestampTokenRequired);
    }
    inline bool operator>(const KeyMintHardwareInfo& rhs) const {
        return std::tie(versionNumber, securityLevel, keyMintName, keyMintAuthorName,
                        timestampTokenRequired) > std::tie(rhs.versionNumber, rhs.securityLevel,
                                                           rhs.keyMintName, rhs.keyMintAuthorName,
                                                           rhs.timestampTokenRequired);
    }
    inline bool operator>=(const KeyMintHardwareInfo& rhs) const {
        return std::tie(versionNumber, securityLevel, keyMintName, keyMintAuthorName,
                        timestampTokenRequired) >= std::tie(rhs.versionNumber, rhs.securityLevel,
                                                            rhs.keyMintName, rhs.keyMintAuthorName,
                                                            rhs.timestampTokenRequired);
    }

    inline std::string toString() const {
        std::ostringstream os;
        os << "KeyMintHardwareInfo{";
        os << "}";
        return os.str();
    }
};
}  // namespace keymaster::javacard::test
