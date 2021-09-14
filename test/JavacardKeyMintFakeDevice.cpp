/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "android.hardware.security.keymint.javacard-impl"
#include "JavacardKeyMintDevice.h"
#include <ErrorCode.h>
#include "JavacardKeyMintOperation.h"
#include <KeyMintUtils.h>
#include <ScopedAStatus.h>
#include <ITransport.h>
#include <SocketTransport.h>
#include <cassert>

//#include <android-base/logging.h>

namespace keymint::javacard {
using namespace keymaster;
// TODO remove the lines below once  
using namespace keymaster::javacard;
using namespace keymaster::javacard::test;

vector<KeyCharacteristics> convertKeyCharacteristics(SecurityLevel keyMintSecurityLevel,
                                                     const AuthorizationSet& sw_enforced,
                                                     const AuthorizationSet& hw_enforced) {
    assert(("bad security level: only STRONGBOX supported",
            keyMintSecurityLevel != SecurityLevel::STRONGBOX));
    KeyCharacteristics keyMintEnforced{keyMintSecurityLevel, {}};
    keyMintEnforced.authorizations = kmParamSet2Aidl(hw_enforced);
    KeyCharacteristics keystoreEnforced{SecurityLevel::KEYSTORE, kmParamSet2Aidl(sw_enforced)};
    return {std::move(keyMintEnforced), std::move(keystoreEnforced)};
}

Certificate convertCertificate(const keymaster_blob_t& cert) {
    return {std::vector<uint8_t>(cert.data, cert.data + cert.data_length)};
}

vector<Certificate> convertCertificateChain(const CertificateChain& chain) {
    vector<Certificate> retval;
    retval.reserve(chain.entry_count);
    std::transform(chain.begin(), chain.end(), std::back_inserter(retval), convertCertificate);
    return retval;
}

// constexpr size_t kOperationTableSize = 16;

JavacardKeyMintDevice::JavacardKeyMintDevice() : securitylevel_(SecurityLevel::STRONGBOX) {
    std::shared_ptr<ITransport> transport = std::make_shared<SocketTransport>();
    proxy_ = std::make_shared<JavacardKeymasterProxy>(StrongBoxVersion::KEYMINT, transport);
}

JavacardKeyMintDevice::~JavacardKeyMintDevice() {}

ScopedAStatus JavacardKeyMintDevice::getHardwareInfo(KeyMintHardwareInfo* info) {
    GetHardwareInfoResponse response(proxy_->version());
    proxy_->GetHardwareInfo(&response);
    info->keyMintAuthorName = response.keymasterAuthorName;
    info->keyMintName = response.keymasterName;
    info->securityLevel = static_cast<SecurityLevel>(response.securityLevel);
    info->timestampTokenRequired = response.timestampTokenRequired;
    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus JavacardKeyMintDevice::addRngEntropy(const vector<uint8_t>& /*data*/) {
    /*
    if (data.size() == 0) {
        return ScopedAStatus::ok();
    }

    AddEntropyRequest request(proxy_->message_version());
    request.random_data.Reinitialize(data.data(), data.size());

    AddEntropyResponse response(proxy_->message_version());
    proxy_->AddRngEntropy(request, &response);

    return kmError2ScopedAStatus(response.error);
    */
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::generateKey(const vector<KeyParameter>& keyParams,
                                                     const optional<AttestationKey>& attestationKey,
                                                     KeyCreationResult* creationResult) {

    GenerateKeyRequest request(proxy_->version());
    request.key_description.Reinitialize(KmParamSet(keyParams));
    if (attestationKey) {
        request.attestation_signing_key_blob =
            KeymasterKeyBlob(attestationKey->keyBlob.data(), attestationKey->keyBlob.size());
        request.attest_key_params.Reinitialize(KmParamSet(attestationKey->attestKeyParams));
        request.issuer_subject = KeymasterBlob(attestationKey->issuerSubjectName.data(),
                                               attestationKey->issuerSubjectName.size());
    }

    GenerateKeyResponse response(proxy_->version());
    proxy_->GenerateKey(request, &response);

    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    creationResult->keyBlob = kmBlob2vector(response.key_blob);
    creationResult->keyCharacteristics =
        convertKeyCharacteristics(securitylevel_, response.unenforced, response.enforced);
    creationResult->certificateChain = convertCertificateChain(response.certificate_chain);

    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardKeyMintDevice::importKey(const vector<KeyParameter>& /*keyParams*/,
                                     KeyFormat /*keyFormat*/, const vector<uint8_t>& /*keyData*/,
                                     const optional<AttestationKey>& /*attestationKey*/,
                                     KeyCreationResult* /*creationResult*/) {
    /*
        ImportKeyRequest request(proxy_->message_version());
        request.key_description.Reinitialize(KmParamSet(keyParams));
        request.key_format = legacy_enum_conversion(keyFormat);
        request.key_data = KeymasterKeyBlob(keyData.data(), keyData.size());
        if (attestationKey) {
            request.attestation_signing_key_blob =
                KeymasterKeyBlob(attestationKey->keyBlob.data(), attestationKey->keyBlob.size());
            request.attest_key_params.Reinitialize(KmParamSet(attestationKey->attestKeyParams));
            request.issuer_subject = KeymasterBlob(attestationKey->issuerSubjectName.data(),
                                                   attestationKey->issuerSubjectName.size());
        }

        ImportKeyResponse response(proxy_->message_version());
        proxy_->ImportKey(request, &response);

        if (response.error != KM_ERROR_OK) {
            return kmError2ScopedAStatus(response.error);
        }

        creationResult->keyBlob = kmBlob2vector(response.key_blob);
        creationResult->keyCharacteristics =
            convertKeyCharacteristics(securityLevel_, response.unenforced, response.enforced);
        creationResult->certificateChain = convertCertificateChain(response.certificate_chain);
    */
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::importWrappedKey(
    const vector<uint8_t>& /*wrappedKeyData*/, const vector<uint8_t>& /*wrappingKeyBlob*/,
    const vector<uint8_t>& /*maskingKey*/, const vector<KeyParameter>& /*unwrappingParams*/,
    int64_t /*passwordSid*/, int64_t /*biometricSid*/, KeyCreationResult* /*creationResult*/) {
    /*
        ImportWrappedKeyRequest request(proxy_->message_version());
        request.SetWrappedMaterial(wrappedKeyData.data(), wrappedKeyData.size());
        request.SetWrappingMaterial(wrappingKeyBlob.data(), wrappingKeyBlob.size());
        request.SetMaskingKeyMaterial(maskingKey.data(), maskingKey.size());
        request.additional_params.Reinitialize(KmParamSet(unwrappingParams));
        request.password_sid = static_cast<uint64_t>(passwordSid);
        request.biometric_sid = static_cast<uint64_t>(biometricSid);

        ImportWrappedKeyResponse response(proxy_->message_version());
        proxy_->ImportWrappedKey(request, &response);

        if (response.error != KM_ERROR_OK) {
            return kmError2ScopedAStatus(response.error);
        }

        creationResult->keyBlob = kmBlob2vector(response.key_blob);
        creationResult->keyCharacteristics =
            convertKeyCharacteristics(securityLevel_, response.unenforced, response.enforced);
        creationResult->certificateChain = convertCertificateChain(response.certificate_chain);
    */
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::upgradeKey(const vector<uint8_t>& /*keyBlobToUpgrade*/,
                                                    const vector<KeyParameter>& /*upgradeParams*/
                                                    ,
                                                    vector<uint8_t>* /*keyBlob*/) {
    /*
        UpgradeKeyRequest request(proxy_->message_version());
        request.SetKeyMaterial(keyBlobToUpgrade.data(), keyBlobToUpgrade.size());
        request.upgrade_params.Reinitialize(KmParamSet(upgradeParams));

        UpgradeKeyResponse response(proxy_->message_version());
        proxy_->UpgradeKey(request, &response);

        if (response.error != KM_ERROR_OK) {
            return kmError2ScopedAStatus(response.error);
        }

        *keyBlob = kmBlob2vector(response.upgraded_key);
    */
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::deleteKey(const vector<uint8_t>& /*keyBlob*/) {
    /*
    DeleteKeyRequest request(proxy_->message_version());
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());

    DeleteKeyResponse response(proxy_->message_version());
    proxy_->DeleteKey(request, &response);

    return kmError2ScopedAStatus(response.error);
    */
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::deleteAllKeys() {
    /*
    // There's nothing to be done to delete software key blobs.
    DeleteAllKeysRequest request(proxy_->message_version());
    DeleteAllKeysResponse response(proxy_->message_version());
    proxy_->DeleteAllKeys(request, &response);

    return kmError2ScopedAStatus(response.error);
    */
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::destroyAttestationIds() {
    /*
    return kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
    */
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::begin(KeyPurpose /*purpose*/,
                                               const vector<uint8_t>& /*keyBlob*/,
                                               const vector<KeyParameter>& /*params*/,
                                               const HardwareAuthToken& /*authToken*/,
                                               BeginResult* /*result*/) {
    /*
        BeginOperationRequest request(proxy_->message_version());
        request.purpose = legacy_enum_conversion(purpose);
        request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
        request.additional_params.Reinitialize(KmParamSet(params));

        vector<uint8_t> vector_token = authToken2AidlVec(authToken);
        request.additional_params.push_back(
            TAG_AUTH_TOKEN, reinterpret_cast<uint8_t*>(vector_token.data()), vector_token.size());

        BeginOperationResponse response(proxy_->message_version());
        proxy_->BeginOperation(request, &response);

        if (response.error != KM_ERROR_OK) {
            return kmError2ScopedAStatus(response.error);
        }

        result->params = kmParamSet2Aidl(response.output_params);
        result->challenge = response.op_handle;
        result->operation =
            ndk::SharedRefBase::make<JavacardKeyMintFakeOperation>(proxy_, response.op_handle,
       proxy_);
    */
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardKeyMintDevice::deviceLocked(bool /*passwordOnly*/,
                                        const std::optional<TimeStampToken>& /*timestampToken*/) {
    /*
        DeviceLockedRequest request(proxy_->message_version());
        request.passwordOnly = passwordOnly;
        if (timestampToken.has_value()) {
            request.token.challenge = timestampToken->challenge;
            request.token.mac = {timestampToken->mac.data(), timestampToken->mac.size()};
            request.token.timestamp = timestampToken->timestamp.milliSeconds;
        }
        DeviceLockedResponse response = proxy_->DeviceLocked(request);
        return kmError2ScopedAStatus(response.error);
        */
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::earlyBootEnded() {
    /*
    EarlyBootEndedResponse response = proxy_->EarlyBootEnded();
    return kmError2ScopedAStatus(response.error);
    */
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintDevice::performOperation(const vector<uint8_t>& /* request */,
                                                          vector<uint8_t>* /* response */) {
    /*
    return kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
    */
    return ScopedAStatus::ok();
}

}  // namespace keymint::javacard
