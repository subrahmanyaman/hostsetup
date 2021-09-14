#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "HardwareAuthToken.h"
#include "TimeStampToken.h"
#include "ScopedAStatus.h"

namespace keymaster::javacard::test {
class IKeyMintOperation {
public:
  explicit IKeyMintOperation(){}
  virtual ~IKeyMintOperation(){}  
  
  virtual ScopedAStatus updateAad(const std::vector<uint8_t>& in_input, const std::optional<HardwareAuthToken>& in_authToken, const std::optional<TimeStampToken>& in_timeStampToken) = 0;
  virtual ScopedAStatus update(const std::vector<uint8_t>& in_input, const std::optional<HardwareAuthToken>& in_authToken, const std::optional<TimeStampToken>& in_timeStampToken, std::vector<uint8_t>* _aidl_return) = 0;
  virtual ScopedAStatus finish(const std::optional<std::vector<uint8_t>>& in_input, const std::optional<std::vector<uint8_t>>& in_signature, const std::optional<HardwareAuthToken>& in_authToken, const std::optional<TimeStampToken>& in_timestampToken, const std::optional<std::vector<uint8_t>>& in_confirmationToken, std::vector<uint8_t>* _aidl_return) = 0;
  virtual ScopedAStatus abort() = 0;
};
}  // namespace keymaster::javacard::test
