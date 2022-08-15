#include "fmt/core.h"
#include "unix_sys.h"
#include "service.h"

#include <unistd.h>
#include <string_view>

using std::string_view;
using asio::io_context;
using conf::ServerConfig;

constexpr string_view VERSION = "v0.1.2";
constexpr string_view CMDUSAGE = 
R"##(trojan -l <addr> -p <port> -k <password> -a <cert> -b <key>

OPTIONS:
    -d              daemonize
    -n <nofile>     set nofile limit
)##";

void init(int argc, char **argv, ServerConfig *config)
{
    int opt;
    int required = 5;

    int fdlmt = 0;
    bool daemon = false;

#define STORE(ident) { config->ident = optarg; required--; break;}
    while((opt = getopt(argc, argv, "vhdn:l:p:k:a:b:")) != -1) {
        switch(opt) {
            default:
                fmt::print("{}", CMDUSAGE);
                std::exit(EXIT_FAILURE);
            case 'v':
                fmt::print("trojan {}\n", VERSION);
                std::exit(EXIT_SUCCESS);
            case 'h':
                fmt::print("{}", CMDUSAGE);
                std::exit(EXIT_SUCCESS);
            // syscall
            case 'd':
                daemon = true;
                break;
            case 'n':
                fdlmt = std::atoi(optarg);
                break;
            // config
            case 'l':
                STORE(host);
            case 'p':
                STORE(port);
            case 'k':
                STORE(password);
            case 'a':
                STORE(crt_path);
            case 'b':
                STORE(key_path);
        }
    }
#undef STORE

    if (required > 0) {
        fmt::print("{}", CMDUSAGE);
        std::exit(EXIT_FAILURE);
    } else {
        config->show();
    }

    if (fdlmt > 0) {
        unix_sys::set_nofile_limit(fdlmt);
    }
    unix_sys::show_nofile_limit();

    if (daemon) {
        unix_sys::daemonize();
    }
}

int main(int argc, char **argv)
{
    io_context ctx;
    ServerConfig config;

    init(argc, argv, &config);

    auto server = service::build_server(ctx, std::move(config));
    asio::co_spawn(ctx, service::run_server(std::move(server)), asio::detached);
    ctx.run();

    return EXIT_FAILURE;
}
