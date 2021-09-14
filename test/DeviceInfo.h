#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
class DeviceInfo {
  public:
    std::vector<uint8_t> deviceInfo;

    inline bool operator!=(const DeviceInfo& rhs) const {
        return std::tie(deviceInfo) != std::tie(rhs.deviceInfo);
    }
    inline bool operator<(const DeviceInfo& rhs) const {
        return std::tie(deviceInfo) < std::tie(rhs.deviceInfo);
    }
    inline bool operator<=(const DeviceInfo& rhs) const {
        return std::tie(deviceInfo) <= std::tie(rhs.deviceInfo);
    }
    inline bool operator==(const DeviceInfo& rhs) const {
        return std::tie(deviceInfo) == std::tie(rhs.deviceInfo);
    }
    inline bool operator>(const DeviceInfo& rhs) const {
        return std::tie(deviceInfo) > std::tie(rhs.deviceInfo);
    }
    inline bool operator>=(const DeviceInfo& rhs) const {
        return std::tie(deviceInfo) >= std::tie(rhs.deviceInfo);
    }

    inline std::string toString() const {
        std::ostringstream os;
        os << "DeviceInfo{";
        os << "}";
        return os.str();
    }
};
}  // namespace keymaster::javacard::test
