#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
namespace keymaster::javacard::test {
enum class PaddingMode : int32_t {
    NONE = 1,
    RSA_OAEP = 2,
    RSA_PSS = 3,
    RSA_PKCS1_1_5_ENCRYPT = 4,
    RSA_PKCS1_1_5_SIGN = 5,
    PKCS7 = 64,
};

static inline std::string toString(PaddingMode val) {
    switch (val) {
    case PaddingMode::NONE:
        return "NONE";
    case PaddingMode::RSA_OAEP:
        return "RSA_OAEP";
    case PaddingMode::RSA_PSS:
        return "RSA_PSS";
    case PaddingMode::RSA_PKCS1_1_5_ENCRYPT:
        return "RSA_PKCS1_1_5_ENCRYPT";
    case PaddingMode::RSA_PKCS1_1_5_SIGN:
        return "RSA_PKCS1_1_5_SIGN";
    case PaddingMode::PKCS7:
        return "PKCS7";
    default:
        return std::to_string(static_cast<int32_t>(val));
    }
}
}  // namespace keymaster::javacard::test