#pragma once
#include "KeyParameter.h"
#include <cstdint>
#include <string>
#include <vector>
namespace keymaster::javacard::test {
class AttestationKey {
  public:
    std::vector<uint8_t> keyBlob;
    std::vector<KeyParameter> attestKeyParams;
    std::vector<uint8_t> issuerSubjectName;

    inline bool operator!=(const AttestationKey& rhs) const {
        return std::tie(keyBlob, attestKeyParams, issuerSubjectName) !=
               std::tie(rhs.keyBlob, rhs.attestKeyParams, rhs.issuerSubjectName);
    }
    inline bool operator<(const AttestationKey& rhs) const {
        return std::tie(keyBlob, attestKeyParams, issuerSubjectName) <
               std::tie(rhs.keyBlob, rhs.attestKeyParams, rhs.issuerSubjectName);
    }
    inline bool operator<=(const AttestationKey& rhs) const {
        return std::tie(keyBlob, attestKeyParams, issuerSubjectName) <=
               std::tie(rhs.keyBlob, rhs.attestKeyParams, rhs.issuerSubjectName);
    }
    inline bool operator==(const AttestationKey& rhs) const {
        return std::tie(keyBlob, attestKeyParams, issuerSubjectName) ==
               std::tie(rhs.keyBlob, rhs.attestKeyParams, rhs.issuerSubjectName);
    }
    inline bool operator>(const AttestationKey& rhs) const {
        return std::tie(keyBlob, attestKeyParams, issuerSubjectName) >
               std::tie(rhs.keyBlob, rhs.attestKeyParams, rhs.issuerSubjectName);
    }
    inline bool operator>=(const AttestationKey& rhs) const {
        return std::tie(keyBlob, attestKeyParams, issuerSubjectName) >=
               std::tie(rhs.keyBlob, rhs.attestKeyParams, rhs.issuerSubjectName);
    }
};
}  // namespace keymaster::javacard::test
