#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "MacedPublicKey.h"
#include "ProtectedData.h"
#include "ScopedAStatus.h"
#include "RpcHardwareInfo.h"
#include "DeviceInfo.h"

namespace keymaster::javacard::test {
class IRemotelyProvisionedComponent {

  
public:
enum : int32_t { STATUS_FAILED = 1 };
  enum : int32_t { STATUS_INVALID_MAC = 2 };
  enum : int32_t { STATUS_PRODUCTION_KEY_IN_TEST_REQUEST = 3 };
  enum : int32_t { STATUS_TEST_KEY_IN_PRODUCTION_REQUEST = 4 };
  enum : int32_t { STATUS_INVALID_EEK = 5 };

  explicit IRemotelyProvisionedComponent(){}
  virtual ~IRemotelyProvisionedComponent(){}
  virtual ScopedAStatus getHardwareInfo(RpcHardwareInfo* info) = 0;
  
  virtual ScopedAStatus generateEcdsaP256KeyPair(bool in_testMode, MacedPublicKey* out_macedPublicKey, std::vector<uint8_t>* _aidl_return) = 0;

 virtual ScopedAStatus generateCertificateRequest(
      bool testMode, const std::vector<MacedPublicKey>& keysToSign,
      const std::vector<uint8_t>& endpointEncCertChain,
      const std::vector<uint8_t>& challenge, DeviceInfo* deviceInfo,
      ProtectedData* protectedData,
      std::vector<uint8_t>* keysToSignMac) = 0;

private:
  static std::shared_ptr<IRemotelyProvisionedComponent> default_impl;
};
}  // namespace keymaster::javacard::test

