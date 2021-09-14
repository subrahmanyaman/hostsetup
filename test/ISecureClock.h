#pragma once

#include "ScopedAStatus.h"
#include "TimeStampToken.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
class ISecureClock {
  public:
    explicit ISecureClock() {}
    virtual ~ISecureClock() {}

    virtual ScopedAStatus generateTimeStamp(int64_t in_challenge, TimeStampToken* _aidl_return) = 0;
};
}  // namespace keymaster::javacard::test
