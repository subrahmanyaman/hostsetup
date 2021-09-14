#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <sstream>
#include <vector>

namespace keymaster::javacard::test {
class Timestamp {
  public:
    int64_t milliSeconds = 0L;

    inline bool operator!=(const Timestamp& rhs) const {
        return std::tie(milliSeconds) != std::tie(rhs.milliSeconds);
    }
    inline bool operator<(const Timestamp& rhs) const {
        return std::tie(milliSeconds) < std::tie(rhs.milliSeconds);
    }
    inline bool operator<=(const Timestamp& rhs) const {
        return std::tie(milliSeconds) <= std::tie(rhs.milliSeconds);
    }
    inline bool operator==(const Timestamp& rhs) const {
        return std::tie(milliSeconds) == std::tie(rhs.milliSeconds);
    }
    inline bool operator>(const Timestamp& rhs) const {
        return std::tie(milliSeconds) > std::tie(rhs.milliSeconds);
    }
    inline bool operator>=(const Timestamp& rhs) const {
        return std::tie(milliSeconds) >= std::tie(rhs.milliSeconds);
    }

    inline std::string toString() const {
        std::ostringstream os;
        os << "Timestamp{";
        os << "}";
        return os.str();
    }
};
}  // namespace keymaster::javacard::test
