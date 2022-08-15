#pragma once

#include <string_view>
#include <fmt/core.h>

using std::string_view;

namespace conf {
    struct ServerConfig {
        inline void show() const noexcept {
            fmt::print("cert={}, key={}, passwd={}\n", this->crt_path, this->key_path, this->password);
            fmt::print("listen {}:{}..\n", this->host, this->port);
        };

        string_view host;
        string_view port;
        string_view password;
        string_view crt_path;
        string_view key_path;
    };
}
