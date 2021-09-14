#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
namespace keymaster::javacard::test {
class RpcHardwareInfo {
public:
  
  int32_t versionNumber = 0;
  std::string rpcAuthorName;
  int32_t supportedEekCurve = 0;

  
  inline bool operator!=(const RpcHardwareInfo& rhs) const {
    return std::tie(versionNumber, rpcAuthorName, supportedEekCurve) != std::tie(rhs.versionNumber, rhs.rpcAuthorName, rhs.supportedEekCurve);
  }
  inline bool operator<(const RpcHardwareInfo& rhs) const {
    return std::tie(versionNumber, rpcAuthorName, supportedEekCurve) < std::tie(rhs.versionNumber, rhs.rpcAuthorName, rhs.supportedEekCurve);
  }
  inline bool operator<=(const RpcHardwareInfo& rhs) const {
    return std::tie(versionNumber, rpcAuthorName, supportedEekCurve) <= std::tie(rhs.versionNumber, rhs.rpcAuthorName, rhs.supportedEekCurve);
  }
  inline bool operator==(const RpcHardwareInfo& rhs) const {
    return std::tie(versionNumber, rpcAuthorName, supportedEekCurve) == std::tie(rhs.versionNumber, rhs.rpcAuthorName, rhs.supportedEekCurve);
  }
  inline bool operator>(const RpcHardwareInfo& rhs) const {
    return std::tie(versionNumber, rpcAuthorName, supportedEekCurve) > std::tie(rhs.versionNumber, rhs.rpcAuthorName, rhs.supportedEekCurve);
  }
  inline bool operator>=(const RpcHardwareInfo& rhs) const {
    return std::tie(versionNumber, rpcAuthorName, supportedEekCurve) >= std::tie(rhs.versionNumber, rhs.rpcAuthorName, rhs.supportedEekCurve);
  }

  enum : int32_t { CURVE_NONE = 0 };
  enum : int32_t { CURVE_P256 = 1 };
  enum : int32_t { CURVE_25519 = 2 };
  inline std::string toString() const {
    std::ostringstream os;
    os << "RpcHardwareInfo{";
    os << "}";
    return os.str();
  }
};
}  // namespace aidl
