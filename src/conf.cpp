#include "conf.h"

#include "fmt/core.h"

namespace conf {
    void ServerConfig::show() const noexcept {
        fmt::print("listen: {}:{}\n", this->host, this->port);
        fmt::print("password: {}\n", this->password);
        fmt::print("cert path: {}\n", this->crt_path);
        fmt::print("key path: {}\n", this->key_path);
    }
}
