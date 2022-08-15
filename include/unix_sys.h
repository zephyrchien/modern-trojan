#pragma once

#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <fmt/core.h>

namespace unix_sys {
    inline void daemonize() noexcept {
        pid_t pid;

        // initial fork
        pid = fork();
        if (pid < 0) {
            fmt::print("failed to daemonize\n");
            std::exit(1);
        }

        // parent process
        if (pid > 0) {
            fmt::print("trojan is running in the background\n");
            std::exit(0);
        };

        // child process
        if (setsid() < 0) std::exit(1);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGHUP, SIG_IGN);

        // second fork
        pid = fork();
        if (pid < 0) std::exit(1);

        // parent process 
        if (pid > 0) std::exit(0);

        // child process
        for (int fd = sysconf(_SC_OPEN_MAX); fd >= 0; --fd) {
            close(fd);
        }
        return;
    }

    inline void show_nofile_limit() noexcept {
        rlimit limit;
        int ret = getrlimit(RLIMIT_NOFILE, &limit);
        if (ret < 0) {
            fmt::print("failed to get fd limit\n");
        } else {
            fmt::print("fd limit: soft={}, hard={}\n", limit.rlim_cur, limit.rlim_max);
        }
    }

    inline void set_nofile_limit(std::size_t nofile) noexcept {
        const rlimit limit = {nofile, nofile};
        int ret = setrlimit(RLIMIT_NOFILE, &limit);
        if (ret < 0) {
            fmt::print("failed to set fd limit to {}\n", nofile);
        } else {
            fmt::print("set fd limit to {}\n", nofile);
        }
    }
}