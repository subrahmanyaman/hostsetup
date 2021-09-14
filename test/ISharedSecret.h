#pragma once

//#include <android/binder_interface_utils.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "SharedSecretParameters.h"
#include "ScopedAStatus.h"

namespace keymaster::javacard::test {

class ISharedSecret {
public:
  //static const char* descriptor;
  ISharedSecret();
  virtual ~ISharedSecret();

  // static const char* KEY_AGREEMENT_LABEL;
  // static const char* KEY_CHECK_LABEL;
  // static constexpr uint32_t TRANSACTION_getSharedSecretParameters = FIRST_CALL_TRANSACTION + 0;
  // static constexpr uint32_t TRANSACTION_computeSharedSecret = FIRST_CALL_TRANSACTION + 1;

  // static std::shared_ptr<ISharedSecret> fromBinder(const ::ndk::SpAIBinder& binder);
  // static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<ISharedSecret>& instance);
  // static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<ISharedSecret>* instance);
  // static bool setDefaultImpl(const std::shared_ptr<ISharedSecret>& impl);
  // static const std::shared_ptr<ISharedSecret>& getDefaultImpl();
  virtual ScopedAStatus getSharedSecretParameters(SharedSecretParameters* _aidl_return) = 0;
  virtual ScopedAStatus computeSharedSecret(const std::vector<SharedSecretParameters>& in_params, std::vector<uint8_t>* _aidl_return) = 0;
//private:
  //static std::shared_ptr<ISharedSecret> default_impl;
};

  // namespace android
}  // namespace aidl
