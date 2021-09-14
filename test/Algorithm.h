#pragma once

#include <cstdint>
#include <string>
namespace keymaster::javacard::test {
enum class Algorithm : int32_t {
    RSA = 1,
    EC = 3,
    AES = 32,
    TRIPLE_DES = 33,
    HMAC = 128,
};

static inline std::string toString(Algorithm val) {
    switch (val) {
    case Algorithm::RSA:
        return "RSA";
    case Algorithm::EC:
        return "EC";
    case Algorithm::AES:
        return "AES";
    case Algorithm::TRIPLE_DES:
        return "TRIPLE_DES";
    case Algorithm::HMAC:
        return "HMAC";
    default:
        return std::to_string(static_cast<int32_t>(val));
    }
}
}  // namespace keymaster::javacard::test
