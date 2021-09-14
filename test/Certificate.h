#pragma once
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>
namespace keymaster::javacard::test {
class Certificate {
  public:
    std::vector<uint8_t> encodedCertificate;

    inline bool operator!=(const Certificate& rhs) const {
        return std::tie(encodedCertificate) != std::tie(rhs.encodedCertificate);
    }
    inline bool operator<(const Certificate& rhs) const {
        return std::tie(encodedCertificate) < std::tie(rhs.encodedCertificate);
    }
    inline bool operator<=(const Certificate& rhs) const {
        return std::tie(encodedCertificate) <= std::tie(rhs.encodedCertificate);
    }
    inline bool operator==(const Certificate& rhs) const {
        return std::tie(encodedCertificate) == std::tie(rhs.encodedCertificate);
    }
    inline bool operator>(const Certificate& rhs) const {
        return std::tie(encodedCertificate) > std::tie(rhs.encodedCertificate);
    }
    inline bool operator>=(const Certificate& rhs) const {
        return std::tie(encodedCertificate) >= std::tie(rhs.encodedCertificate);
    }

    inline std::string toString() const {
        std::ostringstream os;
        os << "Certificate{";
        os << "}";
        return os.str();
    }
};
}  // namespace keymaster::javacard::test
