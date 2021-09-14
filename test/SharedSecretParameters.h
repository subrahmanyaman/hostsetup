#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keymaster::javacard::test {

class SharedSecretParameters {
public:
  // typedef std::false_type fixed_size;
  // static const char* descriptor;

  std::vector<uint8_t> seed;
  std::vector<uint8_t> nonce;

  inline bool operator!=(const SharedSecretParameters& rhs) const {
    return std::tie(seed, nonce) != std::tie(rhs.seed, rhs.nonce);
  }
  inline bool operator<(const SharedSecretParameters& rhs) const {
    return std::tie(seed, nonce) < std::tie(rhs.seed, rhs.nonce);
  }
  inline bool operator<=(const SharedSecretParameters& rhs) const {
    return std::tie(seed, nonce) <= std::tie(rhs.seed, rhs.nonce);
  }
  inline bool operator==(const SharedSecretParameters& rhs) const {
    return std::tie(seed, nonce) == std::tie(rhs.seed, rhs.nonce);
  }
  inline bool operator>(const SharedSecretParameters& rhs) const {
    return std::tie(seed, nonce) > std::tie(rhs.seed, rhs.nonce);
  }
  inline bool operator>=(const SharedSecretParameters& rhs) const {
    return std::tie(seed, nonce) >= std::tie(rhs.seed, rhs.nonce);
  }

  inline std::string toString() const {
    std::ostringstream os;
    os << "SharedSecretParameters{";
    os << "}";
    return os.str();
  }
};
}  // namespace sharedsecret
