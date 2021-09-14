#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
class MacedPublicKey {
  public:
    std::vector<uint8_t> macedKey;

    inline bool operator!=(const MacedPublicKey& rhs) const {
        return std::tie(macedKey) != std::tie(rhs.macedKey);
    }
    inline bool operator<(const MacedPublicKey& rhs) const {
        return std::tie(macedKey) < std::tie(rhs.macedKey);
    }
    inline bool operator<=(const MacedPublicKey& rhs) const {
        return std::tie(macedKey) <= std::tie(rhs.macedKey);
    }
    inline bool operator==(const MacedPublicKey& rhs) const {
        return std::tie(macedKey) == std::tie(rhs.macedKey);
    }
    inline bool operator>(const MacedPublicKey& rhs) const {
        return std::tie(macedKey) > std::tie(rhs.macedKey);
    }
    inline bool operator>=(const MacedPublicKey& rhs) const {
        return std::tie(macedKey) >= std::tie(rhs.macedKey);
    }

    inline std::string toString() const {
        std::ostringstream os;
        os << "MacedPublicKey{";
        os << "}";
        return os.str();
    }
};
}  // namespace keymaster::javacard::test
