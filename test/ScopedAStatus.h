#pragma once

#include "ErrorCode.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#define EX_NONE 0
#define EX_SERVICE_SPECIFIC 1
namespace keymaster::javacard::test {
class ScopedAStatus {
  public:
    ScopedAStatus() { err_ = static_cast<int32_t>(ErrorCode::OK); }
    explicit ScopedAStatus(int32_t error) { err_ = error; }
    ~ScopedAStatus() {}
    ScopedAStatus(ScopedAStatus&&) = default;
    ScopedAStatus& operator=(ScopedAStatus&&) = default;
    static ScopedAStatus ok() { return ScopedAStatus(); }
    bool isOk() const { return err_ == static_cast<int32_t>(ErrorCode::OK); }
    int32_t getServiceSpecificError() const { return err_; }
    static ScopedAStatus fromServiceSpecificError(int32_t error) { return ScopedAStatus(error); }
    bool getExceptionCode() const {
        return (err_ == static_cast<int32_t>(ErrorCode::OK)) ? EX_NONE : EX_SERVICE_SPECIFIC;
    };

  private:
    int32_t err_;
};
}  // namespace keymaster::javacard::test
