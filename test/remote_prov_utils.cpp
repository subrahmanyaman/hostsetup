/*
 * Copyright (c) 2019, The Android Open Source Project
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

#include <iterator>
#include <tuple>
#include <iostream>
#include <sstream>
#include <iomanip>

//#include <aidl/android/hardware/security/keymint/RpcHardwareInfo.h>
#include "RpcHardwareInfo.h"
#include <android-base/properties.h>
#include <cppbor.h>
#include <json/json.h>
#include <keymaster/km_openssl/ec_key.h>
#include <keymaster/km_openssl/ecdsa_operation.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>
#include <openssl/base64.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
//#include <remote_prov/remote_prov_utils.h>
#include "remote_prov_utils.h"

namespace keymaster::javacard::test {

constexpr int kP256AffinePointSize = 32;

using EC_KEY_Ptr = bssl::UniquePtr<EC_KEY>;
using EVP_PKEY_Ptr = bssl::UniquePtr<EVP_PKEY>;
using EVP_PKEY_CTX_Ptr = bssl::UniquePtr<EVP_PKEY_CTX>;

void print(const char* msg, std::vector<uint8_t> data) {
    std::stringstream ss;
    ss << std::hex;
    for (auto ch : data) {
        ss << "0x" << std::right << std::setfill('0') << std::setw(2)  << (int) ch << " ";
    }
    std::cout << msg << std::endl;
    std::cout << ss.str() << std::endl;
}

ErrMsgOr<bytevec> ecKeyGetPrivateKey(const EC_KEY* ecKey) {
    // Extract private key.
    const BIGNUM* bignum = EC_KEY_get0_private_key(ecKey);
    if (bignum == nullptr) {
        return "Error getting bignum from private key";
    }
    int size = BN_num_bytes(bignum);
    // Pad with zeros incase the length is lesser than 32.
    bytevec privKey(32, 0);
    BN_bn2bin(bignum, privKey.data() + 32 - size);
    return privKey;
}

ErrMsgOr<bytevec> ecKeyGetPublicKey(const EC_KEY* ecKey) {
    // Extract public key.
    auto group = EC_GROUP_Ptr(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    if (group.get() == nullptr) {
        return "Error creating EC group by curve name";
    }
    const EC_POINT* point = EC_KEY_get0_public_key(ecKey);
    if (point == nullptr) return "Error getting ecpoint from public key";

    int size = EC_POINT_point2oct(group.get(), point,
                                  POINT_CONVERSION_UNCOMPRESSED, nullptr, 0,
                                  nullptr);
    if (size == 0) {
        return "Error generating public key encoding";
    }

    bytevec publicKey;
    publicKey.resize(size);
    EC_POINT_point2oct(group.get(), point,
                       POINT_CONVERSION_UNCOMPRESSED, publicKey.data(),
                       publicKey.size(), nullptr);
    return publicKey;
}

ErrMsgOr<std::tuple<bytevec, bytevec>> getAffineCoordinates(
    const bytevec& pubKey) {
    auto group = EC_GROUP_Ptr(
        EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    if (group.get() == nullptr) {
        return "Error creating EC group by curve name";
    }
    auto point = EC_POINT_Ptr(EC_POINT_new(group.get()));
    if (EC_POINT_oct2point(group.get(), point.get(), pubKey.data(),
                           pubKey.size(), nullptr) != 1) {
        return "Error decoding publicKey";
    }
    BIGNUM_Ptr x(BN_new());
    BIGNUM_Ptr y(BN_new());
    BN_CTX_Ptr ctx(BN_CTX_new());
    if (!ctx.get()) return "Failed to create BN_CTX instance";

    if (!EC_POINT_get_affine_coordinates_GFp(group.get(), point.get(),
                                             x.get(), y.get(),
                                             ctx.get())) {
        return "Failed to get affine coordinates from ECPoint";
    }
    bytevec pubX(kP256AffinePointSize);
    bytevec pubY(kP256AffinePointSize);
    if (BN_bn2binpad(x.get(), pubX.data(), kP256AffinePointSize) !=
        kP256AffinePointSize) {
        return "Error in converting absolute value of x cordinate to big-endian";
    }
    if (BN_bn2binpad(y.get(), pubY.data(), kP256AffinePointSize) !=
        kP256AffinePointSize) {
        return "Error in converting absolute value of y cordinate to big-endian";
    }
    return std::make_tuple(std::move(pubX), std::move(pubY));
}

ErrMsgOr<std::tuple<bytevec, bytevec>> generateEc256KeyPair() {
    auto ec_key = EC_KEY_Ptr(EC_KEY_new());
    if (ec_key.get() == nullptr) {
        return "Failed to allocate ec key";
    }

    auto group = EC_GROUP_Ptr(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    if (group.get() == nullptr) {
        return "Error creating EC group by curve name";
    }

    if (EC_KEY_set_group(ec_key.get(), group.get()) != 1 ||
        EC_KEY_generate_key(ec_key.get()) != 1 || EC_KEY_check_key(ec_key.get()) < 0) {
        return "Error generating key";
    }

    auto privKey = ecKeyGetPrivateKey(ec_key.get());
    if (!privKey) return privKey.moveMessage();

    auto pubKey = ecKeyGetPublicKey(ec_key.get());
    if (!pubKey) return pubKey.moveMessage();

    return std::make_tuple(pubKey.moveValue(), privKey.moveValue());
}

ErrMsgOr<std::tuple<bytevec, bytevec>> generateX25519KeyPair() {
    /* Generate X25519 key pair */
    bytevec pubKey(X25519_PUBLIC_VALUE_LEN);
    bytevec privKey(X25519_PRIVATE_KEY_LEN);
    X25519_keypair(pubKey.data(), privKey.data());
    return std::make_tuple(std::move(pubKey), std::move(privKey));
}

ErrMsgOr<std::tuple<bytevec, bytevec>> generateED25519KeyPair() {
    /* Generate ED25519 key pair */
    bytevec pubKey(X25519_PUBLIC_VALUE_LEN);
    bytevec privKey(X25519_PRIVATE_KEY_LEN);
    ED25519_keypair(pubKey.data(), privKey.data());
    return std::make_tuple(std::move(pubKey), std::move(privKey));
}

ErrMsgOr<std::tuple<bytevec, bytevec>> generateKeyPair(
    int32_t supportedEekCurve, bool isEek) {

    switch (supportedEekCurve) {
        case RpcHardwareInfo::CURVE_NONE:
        case RpcHardwareInfo::CURVE_25519:
            if (isEek) {
                return generateX25519KeyPair();
            }
            return generateED25519KeyPair();
        case RpcHardwareInfo::CURVE_P256:
            return generateEc256KeyPair();
        default:
            return "Unknown EEK Curve.";
    }
}

ErrMsgOr<bytevec> constructCoseKey(int32_t supportedEekCurve, const bytevec& eekId,
                                   const bytevec& pubKey) {
    CoseKeyType keyType;
    CoseKeyAlgorithm algorithm;
    CoseKeyCurve curve;
    bytevec pubX;
    bytevec pubY;
    switch (supportedEekCurve) {
    case RpcHardwareInfo::CURVE_NONE:
    case RpcHardwareInfo::CURVE_25519:
        keyType = OCTET_KEY_PAIR;
        algorithm = (eekId.empty()) ? EDDSA : ECDH_ES_HKDF_256;
        curve = (eekId.empty()) ? ED25519 : cppcose::X25519;
        pubX = pubKey;
        break;
    case RpcHardwareInfo::CURVE_P256: {
        keyType = EC2;
        algorithm = (eekId.empty()) ? ES256 : ECDH_ES_HKDF_256;
        curve = P256;
        auto affineCoordinates = getAffineCoordinates(pubKey);
        if (!affineCoordinates) return affineCoordinates.moveMessage();
        std::tie(pubX, pubY) = affineCoordinates.moveValue();
    } break;
    default:
        return "Unknown EEK Curve.";
    }
    cppbor::Map coseKey = cppbor::Map()
                              .add(CoseKey::KEY_TYPE, keyType)
                              .add(CoseKey::ALGORITHM, algorithm)
                              .add(CoseKey::CURVE, curve)
                              .add(CoseKey::PUBKEY_X, pubX);

    if (!pubY.empty()) coseKey.add(CoseKey::PUBKEY_Y, pubY);
    if (!eekId.empty()) coseKey.add(CoseKey::KEY_ID, eekId);

    return coseKey.canonicalize().encode();
}

bytevec kTestMacKey(32 /* count */, 0 /* byte value */);

bytevec randomBytes(size_t numBytes) {
    bytevec retval(numBytes);
    RAND_bytes(retval.data(), numBytes);
    return retval;
}

ErrMsgOr<cppbor::Array> constructCoseSign1(int32_t supportedEekCurve, const bytevec& key,
                                           const bytevec& payload, const bytevec& aad) {
  //LOG(ERROR) << "venkat constructCoseSign1 step1 supportedEekCurve " << supportedEekCurve;
    if (supportedEekCurve == RpcHardwareInfo::CURVE_P256) {
  //LOG(ERROR) << "venkat constructCoseSign1 step2";
        return constructECDSACoseSign1(key, {} /* protectedParams */, payload, aad);
    } else {
  //LOG(ERROR) << "venkat constructCoseSign1 step3";
        return cppcose::constructCoseSign1(key, payload, aad);
    }
}

ErrMsgOr<EekChain> generateEekChain(int32_t supportedEekCurve, size_t length,
                                    const bytevec& eekId) {
    if (length < 2) {
        return "EEK chain must contain at least 2 certs.";
    }

    auto eekChain = cppbor::Array();

    bytevec prev_priv_key;
    for (size_t i = 0; i < length - 1; ++i) {
        auto keyPair = generateKeyPair(supportedEekCurve, false);
        if (!keyPair) keyPair.moveMessage();
        auto [pub_key, priv_key] = keyPair.moveValue();

        // The first signing key is self-signed.
        if (prev_priv_key.empty()) prev_priv_key = priv_key;

        auto coseKey = constructCoseKey(supportedEekCurve, {}, pub_key);
        if (!coseKey) return coseKey.moveMessage();

        auto coseSign1 = constructCoseSign1(supportedEekCurve, prev_priv_key, coseKey.moveValue(),
                                            {} /* AAD */);
  //LOG(ERROR) << "venkat generateEekChain step5";
        if (!coseSign1) return coseSign1.moveMessage();
        //cppbor::Array root = coseSign1.moveValue();
        //std::vector<uint8_t> rootCoseSign1 = root.encode();
        //print("EEK ROOT", rootCoseSign1);
        eekChain.add(coseSign1.moveValue());

        prev_priv_key = priv_key;
    }
    auto keyPair = generateKeyPair(supportedEekCurve, true);
    if (!keyPair) keyPair.moveMessage();
    auto [pub_key, priv_key] = keyPair.moveValue();

    auto coseKey = constructCoseKey(supportedEekCurve, eekId, pub_key);
    if (!coseKey) return coseKey.moveMessage();

  //LOG(ERROR) << "venkat generateEekChain step9";
    auto coseSign1 = constructCoseSign1(supportedEekCurve, prev_priv_key, coseKey.moveValue(),
                                        {} /* AAD */);
    if (!coseSign1) return coseSign1.moveMessage();
    //cppbor::Array eek = coseSign1.moveValue();
        //std::vector<uint8_t> eekCoseSign1 = eek.encode();
        //print("GEEK", eekCoseSign1);
        //eekChain.add(std::move(eek));
    eekChain.add(coseSign1.moveValue());

    return EekChain{eekChain.encode(), pub_key, priv_key};
}

bytevec getProdEekChain(int32_t supportedEekCurve) {
    const uint8_t* rootCert = nullptr;
    size_t rootCertLen = 0;
    const uint8_t* geekCert = nullptr;
    size_t geekCertLen = 0;
    if (supportedEekCurve == RpcHardwareInfo::CURVE_P256) {
        rootCert = kCoseEncodedEcdsaRootCert;
        geekCert = kCoseEncodedEcdsaGeekCert;
        rootCertLen = sizeof(kCoseEncodedEcdsaRootCert);
        geekCertLen = sizeof(kCoseEncodedEcdsaGeekCert);
    } else {
        rootCert = kCoseEncodedRootCert;
        geekCert = kCoseEncodedGeekCert;
        rootCertLen = sizeof(kCoseEncodedRootCert);
        geekCertLen = sizeof(kCoseEncodedGeekCert);
    }
    bytevec prodEek;
    prodEek.reserve(1 + rootCertLen + geekCertLen);

    // In CBOR encoding, 0x82 indicates an array of two items
    prodEek.push_back(0x82);
    prodEek.insert(prodEek.end(), rootCert, rootCert + rootCertLen);
    prodEek.insert(prodEek.end(), geekCert, geekCert + geekCertLen);

    return prodEek;
}

ErrMsgOr<bytevec> verifyAndParseCoseSign1Cwt(const cppbor::Array* coseSign1,
                                             const bytevec& signingCoseKey, const bytevec& aad) {
    if (!coseSign1 || coseSign1->size() != kCoseSign1EntryCount) {
        return "Invalid COSE_Sign1";
    }

    const cppbor::Bstr* protectedParams = coseSign1->get(kCoseSign1ProtectedParams)->asBstr();
    const cppbor::Map* unprotectedParams = coseSign1->get(kCoseSign1UnprotectedParams)->asMap();
    const cppbor::Bstr* payload = coseSign1->get(kCoseSign1Payload)->asBstr();
    const cppbor::Bstr* signature = coseSign1->get(kCoseSign1Signature)->asBstr();

    if (!protectedParams || !unprotectedParams || !payload || !signature) {
        return "Invalid COSE_Sign1";
    }

    auto [parsedProtParams, _, errMsg] = cppbor::parse(protectedParams);
    if (!parsedProtParams) {
        return errMsg + " when parsing protected params.";
    }
    if (!parsedProtParams->asMap()) {
        return "Protected params must be a map";
    }

    auto& algorithm = parsedProtParams->asMap()->get(ALGORITHM);
    if (!algorithm || !algorithm->asInt() || (algorithm->asInt()->value() != EDDSA &&
        algorithm->asInt()->value() != ES256)) {
        return "Unsupported signature algorithm";
    }

    // TODO(jbires): Handle CWTs as the CoseSign1 payload in a less hacky way. Since the CWT payload
    //               is extremely remote provisioning specific, probably just make a separate
    //               function there.
    auto [parsedPayload, __, payloadErrMsg] = cppbor::parse(payload);
    if (!parsedPayload) return payloadErrMsg + " when parsing key";
    if (!parsedPayload->asMap()) return "CWT must be a map";
    auto serializedKey = parsedPayload->asMap()->get(-4670552)->clone();
    if (!serializedKey || !serializedKey->asBstr()) return "Could not find key entry";

    bool selfSigned = signingCoseKey.empty();
    bytevec key;
    if (algorithm->asInt()->value() == EDDSA) {
        auto key =
            CoseKey::parseEd25519(selfSigned ? serializedKey->asBstr()->value() : signingCoseKey);
        if (!key) return "Bad signing key: " + key.moveMessage();

        bytevec signatureInput =
            cppbor::Array().add("Signature1").add(*protectedParams).add(aad).add(*payload).encode();

        if (!ED25519_verify(signatureInput.data(), signatureInput.size(), signature->value().data(),
                            key->getBstrValue(CoseKey::PUBKEY_X)->data())) {
            return "Signature verification failed";
        }
    } else { // P256
        auto key =
            CoseKey::parseP256(selfSigned ? serializedKey->asBstr()->value() : signingCoseKey);
        if (!key || key->getBstrValue(CoseKey::PUBKEY_X)->empty() ||
            key->getBstrValue(CoseKey::PUBKEY_Y)->empty()) {
            return "Bad signing key: " + key.moveMessage();
        }
        auto publicKey = key->getEcPublicKey();
        if (!publicKey) return publicKey.moveMessage();

        bytevec signatureInput =
            cppbor::Array().add("Signature1").add(*protectedParams).add(aad).add(*payload).encode();

        if (!verifyEcdsaDigest(publicKey.moveValue(), sha256(signatureInput), signature->value())) {
            return "Signature verification failed";
        }
    }

    return serializedKey->asBstr()->value();
}

ErrMsgOr<std::vector<BccEntryData>> validateBcc(const cppbor::Array* bcc) {
    if (!bcc || bcc->size() == 0) return "Invalid BCC";

    std::vector<BccEntryData> result;

    bytevec prevKey;
    // TODO(jbires): Actually process the pubKey at the start of the new bcc entry
    for (size_t i = 1; i < bcc->size(); ++i) {
        const cppbor::Array* entry = bcc->get(i)->asArray();
        if (!entry || entry->size() != kCoseSign1EntryCount) {
            return "Invalid BCC entry " + std::to_string(i) + ": " + prettyPrint(entry);
        }
        auto payload = verifyAndParseCoseSign1Cwt(entry, std::move(prevKey), bytevec{} /* AAD */);
        if (!payload) {
            return "Failed to verify entry " + std::to_string(i) + ": " + payload.moveMessage();
        }

        auto& certProtParms = entry->get(kCoseSign1ProtectedParams);
        if (!certProtParms || !certProtParms->asBstr()) return "Invalid prot params";
        auto [parsedProtParms, _, errMsg] = cppbor::parse(certProtParms->asBstr()->value());
        if (!parsedProtParms || !parsedProtParms->asMap()) return "Invalid prot params";

        result.push_back(BccEntryData{*payload});

        // This entry's public key is the signing key for the next entry.
        prevKey = payload.moveValue();
    }

    return result;
}

JsonOutput jsonEncodeCsrWithBuild(const cppbor::Array& csr) {
    const std::string kFingerprintProp = "ro.build.fingerprint";

    //if (!::android::base::WaitForPropertyCreation(kFingerprintProp)) {
    //    return JsonOutput::Error("Unable to read build fingerprint");
    //}

    bytevec csrCbor = csr.encode();
    size_t base64Length;
    int rc = EVP_EncodedLength(&base64Length, csrCbor.size());
    if (!rc) {
        return JsonOutput::Error("Error getting base64 length. Size overflow?");
    }

    std::vector<char> base64(base64Length);
    rc = EVP_EncodeBlock(reinterpret_cast<uint8_t*>(base64.data()), csrCbor.data(), csrCbor.size());
    ++rc;  // Account for NUL, which BoringSSL does not for some reason.
    if (rc != base64Length) {
        return JsonOutput::Error("Error writing base64. Expected " + std::to_string(base64Length) +
                                 " bytes to be written, but " + std::to_string(rc) +
                                 " bytes were actually written.");
    }

    Json::Value json(Json::objectValue);
    json["build_fingerprint"] = ::android::base::GetProperty(kFingerprintProp, /*default=*/"");
    json["csr"] = base64.data();  // Boring writes a NUL-terminated c-string

    Json::StreamWriterBuilder factory;
    factory["indentation"] = "";  // disable pretty formatting
    return JsonOutput::Ok(Json::writeString(factory, json));
}

}  // namespace aidl::android::hardware::security::keymint::remote_prov
