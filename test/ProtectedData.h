#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
class ProtectedData {
  public:
    typedef std::false_type fixed_size;
    static const char* descriptor;

    std::vector<uint8_t> protectedData;

    inline bool operator!=(const ProtectedData& rhs) const {
        return std::tie(protectedData) != std::tie(rhs.protectedData);
    }
    inline bool operator<(const ProtectedData& rhs) const {
        return std::tie(protectedData) < std::tie(rhs.protectedData);
    }
    inline bool operator<=(const ProtectedData& rhs) const {
        return std::tie(protectedData) <= std::tie(rhs.protectedData);
    }
    inline bool operator==(const ProtectedData& rhs) const {
        return std::tie(protectedData) == std::tie(rhs.protectedData);
    }
    inline bool operator>(const ProtectedData& rhs) const {
        return std::tie(protectedData) > std::tie(rhs.protectedData);
    }
    inline bool operator>=(const ProtectedData& rhs) const {
        return std::tie(protectedData) >= std::tie(rhs.protectedData);
    }

    inline std::string toString() const {
        std::ostringstream os;
        os << "ProtectedData{";
        os << "}";
        return os.str();
    }
};
}  // namespace keymaster::javacard::test
