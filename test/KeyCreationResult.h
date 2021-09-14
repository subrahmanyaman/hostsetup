#pragma once

#include "Certificate.h"
#include "KeyCharacteristics.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace keymaster::javacard::test {
class KeyCreationResult {
  public:
    std::vector<uint8_t> keyBlob;
    std::vector<KeyCharacteristics> keyCharacteristics;
    std::vector<Certificate> certificateChain;

    inline bool operator!=(const KeyCreationResult& rhs) const {
        return std::tie(keyBlob, keyCharacteristics, certificateChain) !=
               std::tie(rhs.keyBlob, rhs.keyCharacteristics, rhs.certificateChain);
    }
    inline bool operator<(const KeyCreationResult& rhs) const {
        return std::tie(keyBlob, keyCharacteristics, certificateChain) <
               std::tie(rhs.keyBlob, rhs.keyCharacteristics, rhs.certificateChain);
    }
    inline bool operator<=(const KeyCreationResult& rhs) const {
        return std::tie(keyBlob, keyCharacteristics, certificateChain) <=
               std::tie(rhs.keyBlob, rhs.keyCharacteristics, rhs.certificateChain);
    }
    inline bool operator==(const KeyCreationResult& rhs) const {
        return std::tie(keyBlob, keyCharacteristics, certificateChain) ==
               std::tie(rhs.keyBlob, rhs.keyCharacteristics, rhs.certificateChain);
    }
    inline bool operator>(const KeyCreationResult& rhs) const {
        return std::tie(keyBlob, keyCharacteristics, certificateChain) >
               std::tie(rhs.keyBlob, rhs.keyCharacteristics, rhs.certificateChain);
    }
    inline bool operator>=(const KeyCreationResult& rhs) const {
        return std::tie(keyBlob, keyCharacteristics, certificateChain) >=
               std::tie(rhs.keyBlob, rhs.keyCharacteristics, rhs.certificateChain);
    }

    inline std::string toString() const {
        std::ostringstream os;
        os << "KeyCreationResult{";
        os << "}";
        return os.str();
    }
};
}  // namespace keymaster::javacard::test
