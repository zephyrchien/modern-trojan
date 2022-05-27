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
    awaitable<std::pair<int, int>>
    read_until_parsed(_Stream& stream, Slice<uint8_t> buf, _Request& request) noexcept {
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

            auto decode_n = request.decode(buf.slice_until(read_n));

            if (decode_n == -EC::MoreData) [[unlikely]] {
                continue;
            }
            co_return std::pair{decode_n, read_n};
        }        
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
    awaitable<int>
    resolve_addr(const socks5::Address& addr, _Resolver& resolver, _Endpoint* endpoint) noexcept {
        using socks5::helper::overloaded;

        auto port = addr.port;        
        auto ret = co_await std::visit(overloaded {
            [port, endpoint](address ip) -> awaitable<int> {
                *endpoint = _Endpoint(ip, port);
                co_return EC::Ok;
            },
            [port, endpoint, &resolver](const string& addr) -> awaitable<int> {
                auto [ec, result] = co_await resolver.async_resolve(addr, use_await);
                if (ec) { co_return -EC::ErrResolve; }
                *endpoint = *result.begin();
                co_return EC::Ok;
            }
        }, addr.host);

        co_return ret;
    }
}

namespace trojan_server_impl {
    using trojan::Request;
    using service::Server;

    awaitable<void> handle(Server& server, tcp::socket stream) {
        tcp::socket remote_stream(stream.get_executor());
        std::error_code ec;
        stream.set_option(tcp::no_delay(true), ec);
        remote_stream.set_option(tcp::no_delay(true), ec);

        Request request;
        Buffer<uint8_t> buffer;
        Buffer<uint8_t> buffer2;

        // ssl handshake
        ssl_socket ssl_stream(std::move(stream), server.ssl_ctx);
        auto [essl_hs] = co_await ssl_stream.async_handshake(ssl::stream_base::server, use_await);
        if (essl_hs) [[unlikely]] {
            fmt::print("ssl handshake error: {}\n", essl_hs.message()); 
            co_return; 
        }

        // trojan request
        auto [offset_n, offset_m] = co_await common::read_until_parsed(ssl_stream, buffer.slice(), request);
        if (offset_n < 0) [[unlikely]] {
            fmt::print("invalid trojan request\n");
            co_return;
        }

        // check passwd
        if (std::memcmp(request.password.data(), server.password.data(), server.password.size())) {
            fmt::print("incorrect password\n");
            co_return;
        }

        // connect to remote
        tcp::endpoint remote_addr;
        if (co_await common::resolve_addr(request.addr, server.tcp_resolver, &remote_addr) < 0) {
            fmt::print("resolve error\n");
            co_return;
        };
        auto [econn] = co_await remote_stream.async_connect(remote_addr, use_await);
        if (econn) {
            fmt::print("connect to remote error: {}\n", econn.message());
            co_return;
        }

        // write left (n, m) bytes
        if (co_await common::write_all(remote_stream, buffer.slice(offset_n, offset_m)) < 0) {
            co_return;
        };

        // bidi copy
        co_await(
            common::forward(ssl_stream, remote_stream, buffer.slice()) ||
            common::forward(remote_stream, ssl_stream, buffer2.slice())
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

        auto password = hash::sha224((uint8_t*)config.password.data(), config.password.size());

        ssl::context ssl_ctx{ssl::context::sslv23_server};
        ssl_ctx.set_options(SSL_OPTIONS);
        ssl_ctx.use_certificate_chain_file(config.crt_path);
        ssl_ctx.use_private_key_file(config.key_path, ssl::context::pem);
        
        return Server{std::move(listener), std::move(resolver), std::move(ssl_ctx), password};
    }
}
