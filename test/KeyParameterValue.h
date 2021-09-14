#pragma once

#include "Algorithm.h"
#include "BlockMode.h"
#include "Digest.h"
#include "EcCurve.h"
#include "HardwareAuthenticatorType.h"
#include "KeyOrigin.h"
#include "KeyPurpose.h"
#include "PaddingMode.h"
#include "SecurityLevel.h"
#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace keymaster::javacard::test {
class KeyParameterValue {
  public:
    enum Tag : int32_t {
        invalid = 0,                // int invalid;
        algorithm,                  // android.hardware.security.keymint.Algorithm algorithm;
        blockMode,                  // android.hardware.security.keymint.BlockMode blockMode;
        paddingMode,                // android.hardware.security.keymint.PaddingMode paddingMode;
        digest,                     // android.hardware.security.keymint.Digest digest;
        ecCurve,                    // android.hardware.security.keymint.EcCurve ecCurve;
        origin,                     // android.hardware.security.keymint.KeyOrigin origin;
        keyPurpose,                 // android.hardware.security.keymint.KeyPurpose keyPurpose;
        hardwareAuthenticatorType,  // android.hardware.security.keymint.HardwareAuthenticatorType
                                    // hardwareAuthenticatorType;
        securityLevel,  // android.hardware.security.keymint.SecurityLevel securityLevel;
        boolValue,      // boolean boolValue;
        integer,        // int integer;
        longInteger,    // long longInteger;
        dateTime,       // long dateTime;
        blob,           // byte[] blob;
    };

    template <typename _Tp>
    static constexpr bool _not_self =
        !std::is_same_v<std::remove_cv_t<std::remove_reference_t<_Tp>>, KeyParameterValue>;

    KeyParameterValue() : _value(std::in_place_index<invalid>, int32_t(0)) {}
    KeyParameterValue(const KeyParameterValue&) = default;
    KeyParameterValue(KeyParameterValue&&) = default;
    KeyParameterValue& operator=(const KeyParameterValue&) = default;
    KeyParameterValue& operator=(KeyParameterValue&&) = default;

    template <typename _Tp, typename = std::enable_if_t<_not_self<_Tp>>>
    // NOLINTNEXTLINE(google-explicit-constructor)
    constexpr KeyParameterValue(_Tp&& _arg) : _value(std::forward<_Tp>(_arg)) {}

    template <size_t _Np, typename... _Tp>
    constexpr explicit KeyParameterValue(std::in_place_index_t<_Np>, _Tp&&... _args)
        : _value(std::in_place_index<_Np>, std::forward<_Tp>(_args)...) {}

    template <Tag _tag, typename... _Tp> static KeyParameterValue make(_Tp&&... _args) {
        return KeyParameterValue(std::in_place_index<_tag>, std::forward<_Tp>(_args)...);
    }

    template <Tag _tag, typename _Tp, typename... _Up>
    static KeyParameterValue make(std::initializer_list<_Tp> _il, _Up&&... _args) {
        return KeyParameterValue(std::in_place_index<_tag>, std::move(_il),
                                 std::forward<_Up>(_args)...);
    }

    Tag getTag() const { return static_cast<Tag>(_value.index()); }

    template <Tag _tag> const auto& get() const {
    	assert(("bad access : wrong tag", getTag() != _tag));
        return std::get<_tag>(_value);
    }

    template <Tag _tag> auto& get() {
    	assert(("bad access : wrong tag", getTag() != _tag));
        return std::get<_tag>(_value);
    }

    template <Tag _tag, typename... _Tp> void set(_Tp&&... _args) {
        _value.emplace<_tag>(std::forward<_Tp>(_args)...);
    }

    inline bool operator!=(const KeyParameterValue& rhs) const { return _value != rhs._value; }
    inline bool operator<(const KeyParameterValue& rhs) const { return _value < rhs._value; }
    inline bool operator<=(const KeyParameterValue& rhs) const { return _value <= rhs._value; }
    inline bool operator==(const KeyParameterValue& rhs) const { return _value == rhs._value; }
    inline bool operator>(const KeyParameterValue& rhs) const { return _value > rhs._value; }
    inline bool operator>=(const KeyParameterValue& rhs) const { return _value >= rhs._value; }

    inline std::string toString() const {
        std::ostringstream os;
        os << "KeyParameterValue{";
        switch (getTag()) {
        case invalid:
            os << "invalid: ";
            break;
        case algorithm:
            os << "algorithm: ";
            break;
        case blockMode:
            os << "blockMode: ";
            break;
        case paddingMode:
            os << "paddingMode: ";
            break;
        case digest:
            os << "digest: ";
            break;
        case ecCurve:
            os << "ecCurve: ";
            break;
        case origin:
            os << "origin: ";
            break;
        case keyPurpose:
            os << "keyPurpose: ";
            break;
        case hardwareAuthenticatorType:
            os << "hardwareAuthenticatorType: ";
            break;
        case securityLevel:
            os << "securityLevel: ";
            break;
        case boolValue:
            os << "boolValue: ";
            break;
        case integer:
            os << "integer: ";
            break;
        case longInteger:
            os << "longInteger: ";
            break;
        case dateTime:
            os << "dateTime: ";
            break;
        case blob:
            os << "blob: ";
            break;
        }
        os << "}";
        return os.str();
    }

  private:
    std::variant<int32_t, Algorithm, BlockMode, PaddingMode, Digest, EcCurve, KeyOrigin, KeyPurpose,
                 HardwareAuthenticatorType, SecurityLevel, bool, int32_t, int64_t, int64_t,
                 std::vector<uint8_t>>
        _value;
};
}  // namespace keymaster::javacard::test
