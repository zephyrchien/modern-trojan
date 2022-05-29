#include "proto.h"

#include "ec.h"
#include <cassert>

using ec::EC;

namespace socks5 {
    // Encode socks5 addr to provided buffer, return written bytes.
    // It is undefined behavior if dst is not large enough.
    int Address::encode(Slice<uint8_t> dst) const noexcept {
        using helper::overloaded;

        size_t remaining = dst.size();
        // atyp + addr + port
        assert(remaining >= 1 + 255 + 2);

        // write host
        std::visit(overloaded {
            [&dst](address ip){
                if (ip.is_v4()) [[likely]] {
                    dst[0] = ATYP::IPV4;
                    dst.advance(1);
                    auto b = ip.to_v4().to_bytes();
                    std::memcpy(dst.data(), b.data(), b.size());
                    dst.advance(b.size());
                } else {
                    dst[0] = ATYP::IPV6;
                    dst.advance(1);
                    auto b = ip.to_v6().to_bytes();
                    std::memcpy(dst.data(), b.data(), b.size());
                    dst.advance(b.size());
                }
            },
            [&dst](const string& addr) {
                assert(addr.length() > 0 && addr.length() <= 255);
                dst[0] = ATYP::FQDN;
                dst[1] = addr.length();
                dst.advance(2);
                std::memcpy(dst.data(), addr.data(), addr.size());
                dst.advance(addr.size());
            }
        }, this->host);

        // write port
        dst[0] = uint8_t(this->port >> 8);
        dst[1] = uint8_t(this->port & 0x00ff);
        dst.advance(2);
        return remaining - dst.size();
    }

    // Decode socks5 addr from provided buffer, return parsed bytes.
    // Parsed data will be stored in "struct Address".
    int Address::decode(Slice<const uint8_t> src) noexcept {
        size_t remaining = src.size();

        // atyp + ipv4 + port
        if (remaining < (1 + 4 + 2)) [[unlikely]] return -EC::MoreData;

        // parse address
        ATYP atyp = static_cast<ATYP>(src[0]);
        src.advance(1);
        switch (atyp) {
            default: { return -EC::ErrAtyp; }
            case ATYP::IPV4: {
                if (src.size() < 4 + 2) [[unlikely]] return -EC::MoreData;
                this->host = address{address_v4{{src[0], src[1], src[2], src[3]}}};
                src.advance(4);
                break;
            }
            [[unlikely]] case ATYP::IPV6: {
                if (src.size() < 16 + 2) [[unlikely]] return -EC::MoreData;
                this->host = address{address_v6{{
                    src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
                    src[8], src[9], src[10], src[11], src[12], src[13], src[14], src[15], 
                }}};
                src.advance(16);
                break;
            }
            [[likely]] case ATYP::FQDN: {
                if (src.size() < 2) [[unlikely]] return -EC::MoreData;
                size_t len = src[0];
                src.advance(1);
                if (len == 0 || len > 255 ) [[unlikely]] return -EC::ErrFqdnLen;
                if (src.size() < len) return -EC::MoreData;
                // c-style conversion..
                this->host = string((char*)src.data(), len);
                src.advance(len);
                break;
            }
        }

        // parse port
        if (src.size() < 2) [[unlikely]] return -EC::MoreData;
        this->port = uint16_t(src[0]) << 8 | src[1];
        src.advance(2);
        return remaining - src.size();
    }
}


namespace trojan {
    // Encode trojan request to provided buffer, return written bytes.
    // It is undefined behavior if dst is not large enough.
    int Request::encode(Slice<uint8_t> dst) const noexcept {
        int write_n = 0;

        // passwd + crlf + cmd + atyp + addr + port + crlf
        assert(dst.size() >= 56 + 2 + 1 + 1 + 255 + 2 + 2);

        // encode passwd
        std::memcpy(dst.data(), this->password.data(), this->password.size());
        dst.advance(this->password.size());
        write_n += this->password.size();

        // crlf
        dst[0] = CR;
        dst[1] = LF;
        dst.advance(2);
        write_n += 2;

        // encode cmd
        dst[0] = this->cmd;
        dst.advance(1);
        write_n += 1;

        // encode socks5 addr
        if (int ret = this->addr.encode(dst); ret < 0) [[unlikely]] {
            return ret;
        } else {
            dst.advance(ret);
            write_n += ret;
        }

        // crlf
        dst[0] = CR;
        dst[1] = LF;
        dst.advance(2);
        write_n += 2;
        return write_n;
    }

    // Decode trojan request from provided buffer, return parsed bytes.
    // Parsed data will be stored in "struct Request".
    int Request::decode(Slice<const uint8_t> src) noexcept {
        int read_n = 0;

        // passwd + crlf + cmd + atyp + ipv4 + port + crlf
        if (src.size() < (56 + 2 + 1 + 1 + 4 + 2 + 2)) [[unlikely]] return -EC::MoreData;

        // save passwd
        std::memcpy(this->password.data(), src.data(), this->password.size());
        src.advance(this->password.size());
        read_n += this->password.size();

        // crlf
        if (src[0] != CR || src[1] != LF) [[unlikely]] return -EC::ErrCRLF;
        src.advance(2);
        read_n += 2;

        // parse cmd
        this->cmd = src[0];
        src.advance(1);
        read_n += 1;

        // parse socks5 addr
        Address addr;
        if (int ret = addr.decode(src); ret < 0) [[unlikely]] {
            return ret;
        } else {
            src.advance(ret);
            read_n += ret;
        }
        this->addr = std::move(addr);

        // crlf
        if (src.size() < 2) return -EC::MoreData;
        if (src[0] != CR || src[1] != LF) [[unlikely]] return -EC::ErrCRLF;
        src.advance(2);
        read_n += 2;
        return read_n;
    }

    // Encode packet header to provided buffer, return written bytes.
    // It is undefined behavior if dst is not large enough.
    int UdpPacket::encode(Slice<uint8_t> dst) const noexcept {
        int write_n = 0;

        // atyp + addr + port + length + crlf
        assert(dst.size() >= 1 + 255 + 2 + 2 + 2);

        // encode socks5 addr
        if (int ret = this->addr.encode(dst); ret < 0) [[unlikely]] {
            return ret;
        } else {
            dst.advance(ret);
            write_n += ret;
        }

        // encode length
        dst[0] = uint8_t(this->length >> 8);
        dst[1] = uint8_t(this->length & 0x00ff);
        dst.advance(2);
        write_n += 2;

        // crlf
        dst[0] = CR;
        dst[1] = LF;
        dst.advance(2);
        write_n += 2;
        return write_n;
    }

    // Decode packet header from provided buffer, return parsed bytes.
    // Parsed data will be stored in "struct UdpPacket".
    int UdpPacket::decode(Slice<const uint8_t> src) noexcept {
        int read_n = 0;

        // atyp + ipv4 + port + length + crlf
        if (src.size() < (1 + 4 + 2 + 2 + 2)) [[unlikely]] return -EC::MoreData;

        // parse socks5 addr
        Address addr;
        if (int ret = addr.decode(src); ret < 0) [[unlikely]] {
            return ret;
        } else {
            src.advance(ret);
            read_n += ret;
        }
        this->addr = std::move(addr);

        // length + crlf
        if (src.size() < 4) [[unlikely]] return -EC::MoreData;

        // parse length
        this->length = uint16_t(src[0]) << 8 | src[1];
        src.advance(2);
        read_n += 2;

        // crlf
        if (src[0] != CR || src[1] != LF) [[unlikely]] return -EC::ErrCRLF;
        src.advance(2);
        read_n += 2;
        return read_n;
    }
}
