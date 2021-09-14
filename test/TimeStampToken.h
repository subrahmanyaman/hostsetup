#pragma once

#include "Timestamp.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
class TimeStampToken {
  public:
    int64_t challenge = 0L;
    Timestamp timestamp;
    std::vector<uint8_t> mac;

    inline bool operator!=(const TimeStampToken& rhs) const {
        return std::tie(challenge, timestamp, mac) !=
               std::tie(rhs.challenge, rhs.timestamp, rhs.mac);
    }
    inline bool operator<(const TimeStampToken& rhs) const {
        return std::tie(challenge, timestamp, mac) <
               std::tie(rhs.challenge, rhs.timestamp, rhs.mac);
    }
    inline bool operator<=(const TimeStampToken& rhs) const {
        return std::tie(challenge, timestamp, mac) <=
               std::tie(rhs.challenge, rhs.timestamp, rhs.mac);
    }
    inline bool operator==(const TimeStampToken& rhs) const {
        return std::tie(challenge, timestamp, mac) ==
               std::tie(rhs.challenge, rhs.timestamp, rhs.mac);
    }
    inline bool operator>(const TimeStampToken& rhs) const {
        return std::tie(challenge, timestamp, mac) >
               std::tie(rhs.challenge, rhs.timestamp, rhs.mac);
    }
    inline bool operator>=(const TimeStampToken& rhs) const {
        return std::tie(challenge, timestamp, mac) >=
               std::tie(rhs.challenge, rhs.timestamp, rhs.mac);
    }

    inline std::string toString() const {
        std::ostringstream os;
        os << "TimeStampToken{";
        os << "}";
        return os.str();
    }
};
}  // namespace keymaster::javacard::test
