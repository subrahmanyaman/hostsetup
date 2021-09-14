/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "keymint_1_attest_key_test"
#include <cutils/log.h>

#include <keymint_support/key_param_output.h>
#include <keymint_support/openssl_utils.h>

#include "KeyMintAidlTestBase.h"

namespace aidl::android::hardware::security::keymint::test {

namespace {

vector<uint8_t> make_name_from_str(const string& name) {
    X509_NAME_Ptr x509_name(X509_NAME_new());
    EXPECT_TRUE(x509_name.get() != nullptr);
    if (!x509_name) return {};

    EXPECT_EQ(1, X509_NAME_add_entry_by_txt(x509_name.get(),  //
                                            "CN",             //
                                            MBSTRING_ASC,
                                            reinterpret_cast<const uint8_t*>(name.c_str()),
                                            -1,  // len
                                            -1,  // loc
                                            0 /* set */));

    int len = i2d_X509_NAME(x509_name.get(), nullptr /* only return length */);
    EXPECT_GT(len, 0);

    vector<uint8_t> retval(len);
    uint8_t* p = retval.data();
    i2d_X509_NAME(x509_name.get(), &p);

    return retval;
}

bool IsSelfSigned(const vector<Certificate>& chain) {
    if (chain.size() != 1) return false;
    return ChainSignaturesAreValid(chain);
}

}  // namespace

using AttestKeyTest = KeyMintAidlTestBase;

TEST_P(AttestKeyTest, AllRsaSizes) {
    for (auto size : ValidKeySizes(Algorithm::RSA)) {
        /*
         * Create attestaton key.
         */
        AttestationKey attest_key;
        vector<KeyCharacteristics> attest_key_characteristics;
        vector<Certificate> attest_key_cert_chain;
        ASSERT_EQ(ErrorCode::OK, GenerateKey(AuthorizationSetBuilder()
                                                     .RsaSigningKey(size, 65537)
                                                     .AttestKey()
                                                     .SetDefaultValidity(),
                                             {} /* attestation signing key */, &attest_key.keyBlob,
                                             &attest_key_characteristics, &attest_key_cert_chain));

        EXPECT_EQ(attest_key_cert_chain.size(), 1);
        EXPECT_TRUE(IsSelfSigned(attest_key_cert_chain)) << "Failed on size " << size;

        /*
         * Use attestation key to sign RSA key
         */
        attest_key.issuerSubjectName = make_name_from_str("Android Keystore Key");
        vector<uint8_t> attested_key_blob;
        vector<KeyCharacteristics> attested_key_characteristics;
        vector<Certificate> attested_key_cert_chain;
        EXPECT_EQ(ErrorCode::OK,
                  GenerateKey(AuthorizationSetBuilder()
                                      .RsaSigningKey(2048, 65537)
                                      .Authorization(TAG_NO_AUTH_REQUIRED)
                                      .AttestationChallenge("foo")
                                      .AttestationApplicationId("bar")
                                      .SetDefaultValidity(),
                              attest_key, &attested_key_blob, &attested_key_characteristics,
                              &attested_key_cert_chain));

        CheckedDeleteKey(&attested_key_blob);

        AuthorizationSet hw_enforced = HwEnforcedAuthorizations(attested_key_characteristics);
        AuthorizationSet sw_enforced = SwEnforcedAuthorizations(attested_key_characteristics);
        EXPECT_TRUE(verify_attestation_record("foo", "bar", sw_enforced, hw_enforced, SecLevel(),
                                              attested_key_cert_chain[0].encodedCertificate));

        // Attestation by itself is not valid (last entry is not self-signed).
        EXPECT_FALSE(ChainSignaturesAreValid(attested_key_cert_chain));

        // Appending the attest_key chain to the attested_key_chain should yield a valid chain.
        if (attest_key_cert_chain.size() > 0) {
            attested_key_cert_chain.push_back(attest_key_cert_chain[0]);
        }
        EXPECT_TRUE(ChainSignaturesAreValid(attested_key_cert_chain));

        /*
         * Use attestation key to sign EC key
         */
        EXPECT_EQ(ErrorCode::OK,
                  GenerateKey(AuthorizationSetBuilder()
                                      .EcdsaSigningKey(EcCurve::P_256)
                                      .Authorization(TAG_NO_AUTH_REQUIRED)
                                      .AttestationChallenge("foo")
                                      .AttestationApplicationId("bar")
                                      .SetDefaultValidity(),
                              attest_key, &attested_key_blob, &attested_key_characteristics,
                              &attested_key_cert_chain));

        CheckedDeleteKey(&attested_key_blob);
        CheckedDeleteKey(&attest_key.keyBlob);

        hw_enforced = HwEnforcedAuthorizations(attested_key_characteristics);
        sw_enforced = SwEnforcedAuthorizations(attested_key_characteristics);
        EXPECT_TRUE(verify_attestation_record("foo", "bar", sw_enforced, hw_enforced, SecLevel(),
                                              attested_key_cert_chain[0].encodedCertificate));

        // Attestation by itself is not valid (last entry is not self-signed).
        EXPECT_FALSE(ChainSignaturesAreValid(attested_key_cert_chain));

        // Appending the attest_key chain to the attested_key_chain should yield a valid chain.
        if (attest_key_cert_chain.size() > 0) {
            attested_key_cert_chain.push_back(attest_key_cert_chain[0]);
        }
        EXPECT_TRUE(ChainSignaturesAreValid(attested_key_cert_chain));

        // Bail early if anything failed.
        if (HasFailure()) return;
    }
}

TEST_P(AttestKeyTest, AllEcCurves) {
    for (auto curve : ValidCurves()) {
        /*
         * Create attestaton key.
         */
        AttestationKey attest_key;
        vector<KeyCharacteristics> attest_key_characteristics;
        vector<Certificate> attest_key_cert_chain;
        ASSERT_EQ(ErrorCode::OK, GenerateKey(AuthorizationSetBuilder()
                                                     .EcdsaSigningKey(curve)
                                                     .AttestKey()
                                                     .SetDefaultValidity(),
                                             {} /* attestation siging key */, &attest_key.keyBlob,
                                             &attest_key_characteristics, &attest_key_cert_chain));

        EXPECT_EQ(attest_key_cert_chain.size(), 1);
        EXPECT_TRUE(IsSelfSigned(attest_key_cert_chain)) << "Failed on curve " << curve;

        /*
         * Use attestation key to sign RSA key
         */
        attest_key.issuerSubjectName = make_name_from_str("Android Keystore Key");
        vector<uint8_t> attested_key_blob;
        vector<KeyCharacteristics> attested_key_characteristics;
        vector<Certificate> attested_key_cert_chain;
        EXPECT_EQ(ErrorCode::OK,
                  GenerateKey(AuthorizationSetBuilder()
                                      .RsaSigningKey(2048, 65537)
                                      .Authorization(TAG_NO_AUTH_REQUIRED)
                                      .AttestationChallenge("foo")
                                      .AttestationApplicationId("bar")
                                      .SetDefaultValidity(),
                              attest_key, &attested_key_blob, &attested_key_characteristics,
                              &attested_key_cert_chain));

        CheckedDeleteKey(&attested_key_blob);

        AuthorizationSet hw_enforced = HwEnforcedAuthorizations(attested_key_characteristics);
        AuthorizationSet sw_enforced = SwEnforcedAuthorizations(attested_key_characteristics);
        EXPECT_TRUE(verify_attestation_record("foo", "bar", sw_enforced, hw_enforced, SecLevel(),
                                              attested_key_cert_chain[0].encodedCertificate));

        // Attestation by itself is not valid (last entry is not self-signed).
        EXPECT_FALSE(ChainSignaturesAreValid(attested_key_cert_chain));

        // Appending the attest_key chain to the attested_key_chain should yield a valid chain.
        if (attest_key_cert_chain.size() > 0) {
            attested_key_cert_chain.push_back(attest_key_cert_chain[0]);
        }
        EXPECT_TRUE(ChainSignaturesAreValid(attested_key_cert_chain));

        /*
         * Use attestation key to sign EC key
         */
        EXPECT_EQ(ErrorCode::OK,
                  GenerateKey(AuthorizationSetBuilder()
                                      .EcdsaSigningKey(EcCurve::P_256)
                                      .Authorization(TAG_NO_AUTH_REQUIRED)
                                      .AttestationChallenge("foo")
                                      .AttestationApplicationId("bar")
                                      .SetDefaultValidity(),
                              attest_key, &attested_key_blob, &attested_key_characteristics,
                              &attested_key_cert_chain));

        CheckedDeleteKey(&attested_key_blob);
        CheckedDeleteKey(&attest_key.keyBlob);

        hw_enforced = HwEnforcedAuthorizations(attested_key_characteristics);
        sw_enforced = SwEnforcedAuthorizations(attested_key_characteristics);
        EXPECT_TRUE(verify_attestation_record("foo", "bar", sw_enforced, hw_enforced, SecLevel(),
                                              attested_key_cert_chain[0].encodedCertificate));

        // Attestation by itself is not valid (last entry is not self-signed).
        EXPECT_FALSE(ChainSignaturesAreValid(attested_key_cert_chain));

        // Appending the attest_key chain to the attested_key_chain should yield a valid chain.
        if (attest_key_cert_chain.size() > 0) {
            attested_key_cert_chain.push_back(attest_key_cert_chain[0]);
        }
        EXPECT_TRUE(ChainSignaturesAreValid(attested_key_cert_chain));

        // Bail early if anything failed.
        if (HasFailure()) return;
    }
}

INSTANTIATE_KEYMINT_AIDL_TEST(AttestKeyTest);

}  // namespace aidl::android::hardware::security::keymint::test
