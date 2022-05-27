#pragma once

#include <string>

using std::string;

namespace conf {
    struct ServerConfig {
        void show() const noexcept;

        string host;
        string port;
        string password;
        string crt_path;
        string key_path;
    };
}
