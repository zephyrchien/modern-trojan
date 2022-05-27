#include "fmt/core.h"
#include "service.h"

constexpr const char *VERSION = "v0.1.0";

int main(int argc, char **argv)
{
    if (argc != 6 ) return -1;

    asio::io_context ctx;

    auto config = conf::ServerConfig{argv[1], argv[2], argv[3], argv[4], argv[5]};

    config.show();

    auto server = service::build_server(ctx, std::move(config));

    asio::co_spawn(ctx, service::run_server(std::move(server)), asio::detached);

    ctx.run();

    return 0;
}
