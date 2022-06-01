#include "service.h"

#include "asio.hpp"
#include "asio/ssl.hpp"
#include "asio/experimental/as_tuple.hpp"
#include "asio/experimental/awaitable_operators.hpp"

#include "fmt/core.h"

#include "ec.h"
#include "buf.h"
#include "hash.h"
#include "proto.h"

using asio::ip::tcp;
using ssl_socket = asio::ssl::stream<tcp::socket>;
namespace ssl = asio::ssl;

constexpr auto SSL_OPTIONS = (
    ssl::context::default_workarounds | ssl::context::single_dh_use |
    ssl::context::no_sslv2 | ssl::context::no_sslv3 |
    ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1
);

using asio::co_spawn;
using asio::detached;
using asio::awaitable;
using asio::experimental::as_tuple_t;
constexpr auto use_await = asio::experimental::as_tuple(asio::use_awaitable);
namespace this_coro = asio::this_coro;
using namespace asio::experimental::awaitable_operators;

using ec::EC;
using buffer::Slice;
using buffer::Buffer;

namespace common {
    // Read until "Request" is parsed, return <parsed, read> bytes.
    template<typename _Stream, typename _Request>
    awaitable<std::pair<int, int>> read_until_parsed(
        _Stream& stream,
        Slice<uint8_t> buf,
        _Request *request
    ) noexcept {
        size_t read_n = 0;
        
        while (true) {
            auto [ec, n] = co_await stream.async_read_some(
                asio::buffer(buf.data() + read_n, buf.size() - read_n),
                use_await);
            
            // read err or eof
            if (ec || n <= 0) [[unlikely]] {
                co_return std::pair{-EC::ErrRead, -1};
            }
            read_n += n;

            auto decode_n = request->decode(buf.slice_until(read_n));

            if (decode_n == -EC::MoreData) [[unlikely]] {
                continue;
            }
            co_return std::pair{decode_n, read_n};
        }        
    }

    // Read until buffer is filled.
    template<typename _Stream>
    awaitable<int> read_exact(_Stream& stream, Slice<uint8_t> buf) noexcept {
        while (buf.size() > 0) {
            auto [ec, n] = co_await stream.async_read_some(
                asio::buffer(buf.data(), buf.size()),
                use_await);
            
            // read error
            if (ec || n <= 0) [[unlikely]] { co_return -EC::ErrRead; }

            buf.advance(n);
        }
        co_return EC::Ok;
    }

    // Write all data to stream.
    template<typename _Stream> 
    awaitable<int> write_all(_Stream& stream, Slice<const uint8_t> buf) noexcept {
        while (buf.size() > 0) {
            auto [ec, n] = co_await stream.async_write_some(
                asio::buffer(buf.data(), buf.size()),
                use_await);

            // write err
            if (ec || n <=0) [[unlikely]] { co_return -EC::ErrWrite; }

            buf.advance(n);
        }
        co_return EC::Ok;
    }

    // Copy from stream1 to stream2.
    template<typename _Stream1, typename _Stream2>
    awaitable<void> forward(_Stream1& a, _Stream2& b, Slice<uint8_t> buf) noexcept {
        while(true) {
            auto [ec, n] = co_await a.async_read_some(
                asio::buffer(buf.data(), buf.size()),
                use_await);

            // read err or eof
            if (ec || n <= 0) [[unlikely]] { co_return; }

            if (co_await write_all(b, buf.slice_until(n)) < 0) [[unlikely]] { co_return; }
        }
    }

    // Resolve address to tcp/udp endpoint.
    template<typename _Resolver, typename _Endpoint>
    awaitable<int> resolve_addr(
        _Resolver& resolver,
        const socks5::Address& addr,
        _Endpoint *endpoint
    ) noexcept {
        using socks5::helper::overloaded;

        auto port = addr.port;        
        auto ret = co_await std::visit(overloaded {
            [port, endpoint](address ip) -> awaitable<int> {
                *endpoint = _Endpoint(ip, port);
                co_return EC::Ok;
            },
            [port, endpoint, &resolver](const string& addr) -> awaitable<int> {
                auto [ec, result] = co_await resolver.async_resolve(addr, "", use_await);
                if (ec) { co_return -EC::ErrResolve; }
                *endpoint = *result.begin();
                endpoint->port(port);
                co_return EC::Ok;
            }
        }, addr.host);

        co_return ret;
    }
}

namespace trojan_server_impl {
    using trojan::Request;
    using service::Server;
    using common::read_exact;
    using common::read_until_parsed;
    using common::write_all;
    using common::forward;
    using common::resolve_addr;

    awaitable<void> handle_udp(
        Server& server,
        ssl_socket& ssl_stream,
        Slice<uint8_t> buf1, Slice<uint8_t> buf2,
        int offset
    ) noexcept {
        udp::socket udp_socket(ssl_stream.get_executor());
        // first packet
        {
            std::error_code ec;
            trojan::UdpPacket pkt_hdr;
            udp::endpoint remote_addr;
            // atyp + addr[0]
            if (offset < 2) {
                if (co_await read_exact(ssl_stream, buf1.slice(offset, 2)) < 0) { co_return; }
            }

            // port + length + crlf
            auto more_required = 2 + 2 + 2;
            switch (buf1[0]) {
                case socks5::ATYP::IPV4: { more_required += 4 - 1; break; }
                case socks5::ATYP::IPV6: { more_required += 16 - 1; break;}
                case socks5::ATYP::FQDN: { more_required += buf1[1]; break; }
                default: { co_return; }
            }

            // read left bytes of packet header
            if (offset < more_required + 2) {
                if (co_await read_exact(ssl_stream, buf1.slice(std::max(offset, 2), more_required)) < 0) {
                    co_return;
                }
            }

            // parse packet header
            if (pkt_hdr.decode(buf1.slice_until(more_required + 2)) < 0) { co_return; }

            if (pkt_hdr.length > buffer::BUF_SIZE) { co_return; }

            // read payload data
            if (co_await read_exact(ssl_stream, buf1.slice_until(pkt_hdr.length)) < 0) { co_return; }

            // resolve remote addr
            if (co_await resolve_addr(server.udp_resolver, pkt_hdr.addr, &remote_addr) < 0){ co_return; }

            // open and bind udp socket
            udp_socket.open(remote_addr.protocol(), ec);
            if (ec) { co_return; }
            udp_socket.bind(udp::endpoint(remote_addr.protocol(), 0), ec);
            if (ec) { co_return; }
            udp_socket.set_option(udp::socket::reuse_address(true), ec);

            // send udp packet
            auto [ec2, send_n] = co_await udp_socket.async_send_to(
                asio::buffer(buf1.data(), pkt_hdr.length),
                remote_addr, use_await);
            if (ec2) { co_return; }
        }


        auto udp_to_tcp = [&ssl_stream, &udp_socket, buf2]() -> awaitable<void> {
            udp::endpoint addr;
            array<uint8_t, 256> hdr_buf; 

            while (true) {
                // read from remote
                auto [ec, recv_n] = co_await udp_socket.async_receive_from(
                    asio::buffer(buf2.data(), buf2.size()),
                    addr, use_await);
                if (ec) { co_return; }

                // BUF_SIZE < u16::MAX
                trojan::UdpPacket pkt_hdr{addr.address(), uint16_t(recv_n)};
                size_t hdr_len = pkt_hdr.encode({ hdr_buf.data(), hdr_buf.size() });

                // write udp header
                if (co_await write_all(ssl_stream, { hdr_buf.data(), hdr_len }) < 0) {
                    co_return;
                }

                // write udp payload
                if (co_await write_all(ssl_stream, buf2.slice_until(recv_n)) < 0) {
                    co_return;
                }
            }
        };

        auto tcp_to_udp = [&server, &ssl_stream, &udp_socket, buf1, offset]() -> awaitable<void> {
            udp::endpoint remote_addr;
            trojan::UdpPacket pkt_hdr;
            while(true) {
                // read atyp + addr[0]
                if (co_await read_exact(ssl_stream, buf1.slice_until(2)) < 0) { co_return; }
                // port + length + crlf
                auto more_required = 2 + 2 + 2;
                switch (buf1[0]) {
                    case socks5::ATYP::IPV4: { more_required += 4 - 1; break; }
                    case socks5::ATYP::IPV6: { more_required += 16 - 1; break;}
                    case socks5::ATYP::FQDN: { more_required += buf1[1]; break; }
                    default: { co_return; }
                }
                // read left bytes of packet header
                if (co_await read_exact(ssl_stream, buf1.slice(2, more_required)) < 0) {
                    co_return;
                }
                // parse packet header
                if (pkt_hdr.decode(buf1.slice_until(more_required + 2)) < 0) { co_return; }

                if (pkt_hdr.length > buffer::BUF_SIZE) { co_return; }

                // read payload data
                if (co_await read_exact(ssl_stream, buf1.slice_until(pkt_hdr.length)) < 0) { co_return; }

                // resolve remote addr
                if (co_await resolve_addr(server.udp_resolver, pkt_hdr.addr, &remote_addr) < 0){ co_return; }

                // send udp packet
                auto [ec, send_n] = co_await udp_socket.async_send_to(
                    asio::buffer(buf1.data(), pkt_hdr.length),
                    remote_addr, use_await);
                if (ec) { co_return; }
            }
        };

        co_await(tcp_to_udp() || udp_to_tcp());
    }

    awaitable<void> handle(Server& server, tcp::socket stream) noexcept {
        tcp::socket remote_stream(stream.get_executor());
        std::error_code ec;
        stream.set_option(tcp::no_delay(true), ec);
        remote_stream.set_option(tcp::no_delay(true), ec);

        Request request;
        Buffer<uint8_t> buffer1;
        Buffer<uint8_t> buffer2;

        // ssl handshake
        ssl_socket ssl_stream(std::move(stream), server.ssl_ctx);
        auto [essl_hs] = co_await ssl_stream.async_handshake(ssl::stream_base::server, use_await);
        if (essl_hs) [[unlikely]] {
            fmt::print("ssl handshake error: {}\n", essl_hs.message()); 
            co_return; 
        }

        // trojan request
        auto [parsed_n, read_n] = co_await read_until_parsed(ssl_stream, buffer1.slice(), &request);
        if (parsed_n < 0) [[unlikely]] {
            fmt::print("invalid trojan request\n");
            co_return;
        }

        // check passwd
        if (std::memcmp(request.password.data(), server.password.data(), server.password.size())) {
            fmt::print("incorrect password\n");
            co_return;
        }

        // ####################
        // goto udp
        if (request.cmd == trojan::CMD::ASSOCIATE) [[unlikely]] {
            size_t len = read_n - parsed_n;
            if (len > 0) {
                std::memcpy(buffer1.data(), buffer1.data() + parsed_n, len);
            }
            co_await handle_udp(server, ssl_stream, buffer1.slice(), buffer2.slice(), len);
            co_return;
        }
        // ####################

        // handle tcp

        // connect to remote
        tcp::endpoint remote_addr;
        if (co_await resolve_addr(server.tcp_resolver, request.addr, &remote_addr) < 0) [[unlikely]] {
            fmt::print("resolve error\n");
            co_return;
        };
        auto [econn] = co_await remote_stream.async_connect(remote_addr, use_await);
        if (econn) {
            fmt::print("connect to remote error: {}\n", econn.message());
            co_return;
        }

        // write left (n, m) bytes
        if (co_await write_all(remote_stream, buffer1.slice(parsed_n, read_n)) < 0) [[unlikely]] {
            co_return;
        };

        // bidi copy
        co_await(
            forward(ssl_stream, remote_stream, buffer1.slice()) ||
            forward(remote_stream, ssl_stream, buffer2.slice())
        );
    }
}

namespace service_impl {
    template<typename _Provider, typename _Handler>
    awaitable<void> run_service(_Provider provider, _Handler handle) noexcept {
        auto ctx = provider.listen.get_executor();

        while(true) {
            auto [ec, stream] = co_await provider.listen.async_accept(use_await);

            if (ec) [[unlikely]] {
                fmt::print("failed to accept: {}\n", ec.message());
                break;
            }

            co_spawn(ctx, handle(provider, std::move(stream)), detached);
        }
    }
}

namespace service {
    // Launch a server.
    awaitable<void> run_server(Server server) noexcept {
        using service_impl::run_service;
        using trojan_server_impl::handle;
        co_await run_service(std::move(server), handle);
    }

    // Setup a server, may throw exceptions.
    Server build_server(io_context& ctx, ServerConfig config) {
        tcp::resolver resolver(ctx);
        tcp::endpoint listen_addr = *resolver.resolve(config.host, config.port);
        tcp::acceptor listener(ctx, listen_addr);

        listener.set_option(tcp::acceptor::reuse_address(true));

        auto password = hash::sha224((uint8_t*)config.password.data(), config.password.size());

        ssl::context ssl_ctx{ssl::context::sslv23_server};
        ssl_ctx.set_options(SSL_OPTIONS);
        ssl_ctx.use_certificate_chain_file(config.crt_path);
        ssl_ctx.use_private_key_file(config.key_path, ssl::context::pem);
        
        return Server {
            std::move(listener),
            std::move(resolver),
            udp::resolver(ctx),
            std::move(ssl_ctx),
            password
        };
    }
}
