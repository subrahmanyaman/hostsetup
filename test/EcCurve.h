#pragma once

#include <cstdint>
#include <string>

namespace keymaster::javacard::test {
enum class EcCurve : int32_t {
    P_224 = 0,
    P_256 = 1,
    P_384 = 2,
    P_521 = 3,
};

static inline std::string toString(EcCurve val) {
    switch (val) {
    case EcCurve::P_224:
        return "P_224";
    case EcCurve::P_256:
        return "P_256";
    case EcCurve::P_384:
        return "P_384";
    case EcCurve::P_521:
        return "P_521";
    default:
        return std::to_string(static_cast<int32_t>(val));
    }
}
}  // namespace keymaster::javacard::test