#pragma once

#include <string>
#include <fmt/core.h>

using std::string;

namespace conf {
    struct ServerConfig {
        inline void show() const noexcept {
            fmt::print("cert={}, key={}, passwd={}\n", this->crt_path, this->key_path, this->password);
            fmt::print("listen {}:{}..\n", this->host, this->port);
        };

        string host;
        string port;
        string password;
        string crt_path;
        string key_path;
    };
}
