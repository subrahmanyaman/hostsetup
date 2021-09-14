#pragma once

#include "AttestationKey.h"
#include "BeginResult.h"
#include "HardwareAuthToken.h"
#include "KeyCreationResult.h"
#include "KeyFormat.h"
#include "KeyMintHardwareInfo.h"
#include "KeyParameter.h"
#include "KeyPurpose.h"
#include "ScopedAStatus.h"
#include "TimeStampToken.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
class IKeyMintDevice {
  public:
    explicit IKeyMintDevice() {}
    virtual ~IKeyMintDevice() {}

    virtual ScopedAStatus getHardwareInfo(KeyMintHardwareInfo* info)  = 0;

    virtual ScopedAStatus addRngEntropy(const std::vector<uint8_t>& data)  = 0;

    virtual ScopedAStatus generateKey(const std::vector<KeyParameter>& keyParams,
                              const std::optional<AttestationKey>& attestationKey,
                              KeyCreationResult* creationResult)  = 0;

    virtual ScopedAStatus importKey(const std::vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                            const std::vector<uint8_t>& keyData,
                            const std::optional<AttestationKey>& attestationKey,
                            KeyCreationResult* creationResult)  = 0;

    virtual ScopedAStatus importWrappedKey(const std::vector<uint8_t>& wrappedKeyData,
                                   const std::vector<uint8_t>& wrappingKeyBlob,
                                   const std::vector<uint8_t>& maskingKey,
                                   const std::vector<KeyParameter>& unwrappingParams,
                                   int64_t passwordSid, int64_t biometricSid,
                                   KeyCreationResult* creationResult)  = 0;

    virtual ScopedAStatus upgradeKey(const std::vector<uint8_t>& keyBlobToUpgrade,
                             const std::vector<KeyParameter>& upgradeParams,
                             std::vector<uint8_t>* keyBlob)  = 0;

    virtual ScopedAStatus deleteKey(const std::vector<uint8_t>& keyBlob)  = 0;
    virtual ScopedAStatus deleteAllKeys()  = 0;
    virtual ScopedAStatus destroyAttestationIds()  = 0;

    virtual ScopedAStatus begin(KeyPurpose in_purpose, const std::vector<uint8_t>& in_keyBlob,
                                const std::vector<KeyParameter>& in_params,
                                const std::optional<HardwareAuthToken>& in_authToken,
                                BeginResult* _aidl_return)  = 0;

    virtual ScopedAStatus deviceLocked(bool passwordOnly,
                               const std::optional<TimeStampToken>& timestampToken)  = 0;

    virtual ScopedAStatus earlyBootEnded()  = 0;

    virtual ScopedAStatus getKeyCharacteristics(const std::vector<uint8_t>& in_keyBlob,
                                        const std::vector<uint8_t>& in_appId,
                                        const std::vector<uint8_t>& in_appData,
                                        std::vector<KeyCharacteristics>* _aidl_return)  = 0;

    virtual ScopedAStatus convertStorageKeyToEphemeral(const std::vector<uint8_t>& storageKeyBlob,
                                               std::vector<uint8_t>* ephemeralKeyBlob)  = 0;
};
}  // namespace keymaster::javacard::test
