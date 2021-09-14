#pragma once
#include "IKeyMintOperation.h"
#include "KeyParameter.h"
#include <cstdint>
#include <vector>

namespace keymaster::javacard::test {
class BeginResult {
  public:
    int64_t challenge = 0L;
    std::vector<KeyParameter> params;
    std::shared_ptr<IKeyMintOperation> operation;

    inline bool operator!=(const BeginResult& rhs) const {
        return std::tie(challenge, params, operation) !=
               std::tie(rhs.challenge, rhs.params, rhs.operation);
    }
    inline bool operator<(const BeginResult& rhs) const {
        return std::tie(challenge, params, operation) <
               std::tie(rhs.challenge, rhs.params, rhs.operation);
    }
    inline bool operator<=(const BeginResult& rhs) const {
        return std::tie(challenge, params, operation) <=
               std::tie(rhs.challenge, rhs.params, rhs.operation);
    }
    inline bool operator==(const BeginResult& rhs) const {
        return std::tie(challenge, params, operation) ==
               std::tie(rhs.challenge, rhs.params, rhs.operation);
    }
    inline bool operator>(const BeginResult& rhs) const {
        return std::tie(challenge, params, operation) >
               std::tie(rhs.challenge, rhs.params, rhs.operation);
    }
    inline bool operator>=(const BeginResult& rhs) const {
        return std::tie(challenge, params, operation) >=
               std::tie(rhs.challenge, rhs.params, rhs.operation);
    }
};

}  // namespace keymaster::javacard::test
