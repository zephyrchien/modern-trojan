#include "fmt/core.h"
#include "unix_sys.h"
#include "service.h"

#include <iostream>

constexpr const char *VERSION = "v0.1.1";

#if defined(TROJAN_RUN_INTERACTIVE)
void interactive()
{
    std::string input;

    // fd limit
    show_nofile_limit();
    fmt::print("would you like to adjust fd limit? [int/0(default)]\n");
    std::getline(std::cin, input);
    if (!input.empty()) {
        if (int limit = std::stoi(input); limit > 0) {
            set_nofile_limit(limit);
        }
        input.clear();
    }

    // daemonize
    fmt::print("would you like to daemonize? [y/n(default)]\n");
    std::getline(std::cin, input);
    if (!input.empty() && input[0] == 'y') {
        daemonize();
        input.clear();
    }
}
#endif

int main(int argc, char **argv)
{
    if (argc != 6 ) return -1;

    asio::io_context ctx;

    auto config = conf::ServerConfig{argv[1], argv[2], argv[3], argv[4], argv[5]};

    config.show();

#if defined(TROJAN_RUN_INTERACTIVE)
    try {
        interactive();
#endif

    auto server = service::build_server(ctx, std::move(config));

    asio::co_spawn(ctx, service::run_server(std::move(server)), asio::detached);

    ctx.run();

#if defined(TROJAN_RUN_INTERACTIVE)
    } catch(const std::exception& e) {
        fmt::print("{}\n", e.what());
        std::exit(1);
    }
#endif
    std::exit(0);
}
