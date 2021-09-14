#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
namespace keymaster::javacard::test{
enum class BlockMode : int32_t {
  ECB = 1,
  CBC = 2,
  CTR = 3,
  GCM = 32,
};
static inline std::string toString(BlockMode val) {
  switch(val) {
  case BlockMode::ECB:
    return "ECB";
  case BlockMode::CBC:
    return "CBC";
  case BlockMode::CTR:
    return "CTR";
  case BlockMode::GCM:
    return "GCM";
  default:
    return std::to_string(static_cast<int32_t>(val));
  }
}
}  // keymaster::javacard::test

