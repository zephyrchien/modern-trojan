#pragma once

#include <cstdint>
#include <array>
#include <string>
#include <variant>
#include "asio.hpp"
#include "buf.h"

using std::array;
using std::string;
using std::variant;
using asio::ip::address;
using asio::ip::address_v4;
using asio::ip::address_v6;
using buffer::Slice;


namespace socks5 {
    constexpr uint8_t VER = 0x05;
    constexpr uint8_t RSV = 0x00;
    enum CMD: uint8_t {
        CONNECT = 0x01,
        BIND = 0x02,
        ASSOCIATE = 0x03
    };
    enum ATYP: uint8_t {
        IPV4 = 0x01,
        FQDN = 0x03,
        IPV6 = 0x04
    };

    struct Address {
        using Host = variant<address, string>;

        // Encode socks5 addr to provided buffer, return written bytes.
        // It is undefined behavior if dst is not large enough.
        int encode(Slice<uint8_t> dst) const noexcept;

        // Decode socks5 addr from provided buffer, return parsed bytes.
        // Parsed data will be stored in "struct Address".        
        int decode(Slice<const uint8_t> src) noexcept;

        Host host;
        uint16_t port;
    };
    
    namespace helper {
        template<class... Ts>
        struct overloaded : Ts... {
            using Ts::operator()...; 
        };
    }
}

namespace trojan {
    using Address = socks5::Address;
    using CMD = socks5::CMD;
    constexpr uint8_t CR = 0x0d;
    constexpr uint8_t LF = 0x0a;

    struct Request {
        // Encode trojan request to provided buffer, return written bytes.
        // It is undefined behavior if dst is not large enough.
        int encode(Slice<uint8_t> dst) const noexcept;

        // Decode trojan request from provided buffer, return parsed bytes.
        // Parsed data will be stored in "struct Request".        
        int decode(Slice<const uint8_t> src) noexcept;

        uint8_t cmd;
        Address addr;
        array<uint8_t, 56> password;
    };

    struct UdpPacket {
        // Encode packet header to provided buffer, return written bytes.
        // It is undefined behavior if dst is not large enough.
        int encode(Slice<uint8_t> dst) const noexcept;

        // Decode packet header from provided buffer, return parsed bytes.
        // Parsed data will be stored in "struct UdpPacket".        
        int decode(Slice<const uint8_t> src) noexcept;

        Address addr;
        uint16_t length;
    };
}
