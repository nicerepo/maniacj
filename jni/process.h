//===------------------------------------------------------------------------------------------===//
//
//                        The MANIAC Dynamic Binary Instrumentation Engine
//
//===------------------------------------------------------------------------------------------===//
//
// Copyright (C) 2018 Libre.io Developers
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
//===------------------------------------------------------------------------------------------===//
//
// process.h
//
//===------------------------------------------------------------------------------------------===//

#pragma once

#include <cstdint>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <linux/elf.h>
#include <mutex>
#include <random>
#include <string>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#include "memory.h"
#include "regs.h"

#if defined(__LP64__)
#define LIBC std::string("/system/lib64/libc.so")
#define LIBDIR std::string("/system/lib64/")
#else
#define LIBC std::string("/system/lib/libc.so")
#define LIBDIR std::string("/system/lib/")
#endif

class Process {
public:
    Process(pid_t pid)
    {
        char cmd_path[32];
        sprintf(cmd_path, "/proc/%d/cmdline", pid);

        std::ifstream cmd_file(cmd_path);
        std::string cmd_line;
        std::getline(cmd_file, cmd_line, '\0');

        if (cmd_line.empty())
            pid = -1;

        m_pname = cmd_line;
        m_pids.push_back(pid);

        this->prefresh();
    }

    Process(const std::string& pname)
    {
        DIR* dp = opendir("/proc");

        if (!dp) {
            closedir(dp);
            return;
        }

        pid_t pid_entry = -1;
        struct dirent* dirp = nullptr;

        while (pid_entry == -1 && (dirp = readdir(dp))) {
            int id = atoi(dirp->d_name);

            if (id <= 0)
                continue;

            char cmd_path[32];
            sprintf(cmd_path, "/proc/%s/cmdline", dirp->d_name);

            std::ifstream cmd_file(cmd_path);
            std::string cmd_line;
            std::getline(cmd_file, cmd_line, '\0');

            if (cmd_line == pname) {
                pid_entry = id;
                break;
            }
        }

        closedir(dp);

        m_pname = pname;
        m_pids.push_back(pid_entry);

        this->prefresh();
    }

    bool alive() const
    {
        return getpgid(this->m_pids[0]) >= 0;
    }

    pid_t rpid() const
    {
        return m_pids.front();
    }

    const std::vector<pid_t>& pids() const
    {
        return m_pids;
    }

    pid_t prefresh()
    {
        pid_t rpid = m_pids.front();

        DIR* pid_dir;
        char pid_path[32];
        sprintf(pid_path, "/proc/%d/task/", rpid);

        if ((pid_dir = opendir(pid_path)) == nullptr)
            return -1;

        struct dirent* directory_entry = nullptr;

        m_pids.clear();
        m_pids.push_back(rpid);

        while ((directory_entry = readdir(pid_dir)) != nullptr)
            m_pids.push_back(atoi(directory_entry->d_name));

        closedir(pid_dir);

        return m_pids.back();
    }

    void attach()
    {
        if (!this->alive() || m_attached)
            return;

        m_traceid = m_pids.front();

        if (ptrace(PTRACE_ATTACH, m_traceid, nullptr, nullptr) == -1)
            exit(-1);

        if (waitpid(m_traceid, nullptr, WUNTRACED) != m_traceid)
            exit(-1);

        m_attached = true;
    }

    void detach()
    {
        if (!this->alive() || !m_attached)
            return;

        if (ptrace(PTRACE_DETACH, m_traceid, nullptr, nullptr) == -1)
            exit(-1);

        m_attached = false;
    }

    void inject(const std::string& path)
    {
        if (!this->alive() || !m_attached)
            return;

        std::lock_guard<std::mutex> guard(m_mutex);

        std::string copy_path(LIBDIR);

        // stage 1: generate a random name
        {
            std::string str("0123456789"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "abcdefghijklmnopqrstuvwxyz"
                            "-__");

            auto gen(std::random_device{});
            std::shuffle(str.begin(), str.end(), gen);

            copy_path += "lib" + str.substr(0, 7) + ".so";
        }

        // stage 2: copy file to /system/lib (to bypass SELinux)
        {
            mount(nullptr, "/system", nullptr, MS_MGC_VAL | MS_REMOUNT, "");

            std::ifstream src(path, std::ios::binary);
            std::ofstream dst(copy_path, std::ios::binary);

            dst << src.rdbuf();

            chmod(copy_path.data(), 0644);
            mount(nullptr, "/system", nullptr, MS_MGC_VAL | MS_RDONLY | MS_REMOUNT, "");
        }

        // stage 3: inject library to the remote process
        intptr_t from = reinterpret_cast<intptr_t>(copy_path.data());
        intptr_t to = allocate_memory();

        {
            // treat signed integers with care
            if (to == -1 || to == 0)
                exit(-1);

            this->write_mem(from, to, copy_path.length() + 1);

#if 0
            intptr_t remote_dlopen = find_remote_function((intptr_t)::dlopen);

            if (!remote_dlopen)
                exit(-1);

            this->call_function(remote_dlopen, 2, to, RTLD_NOW | RTLD_GLOBAL);
#else
            void* handle = dlopen("libdl.so", RTLD_GLOBAL | RTLD_NOW);
            void* (*__loader_dlopen)(const char*, int)
                = (void* (*)(const char*, int))dlsym(handle, "__loader_dlopen");

            intptr_t remote_dlopen = find_remote_function((intptr_t)__loader_dlopen);

            dlclose(handle);

            if (!remote_dlopen)
                exit(-1);

            intptr_t remote_open = find_remote_function((intptr_t)::open);
            this->call_function(remote_dlopen, 3, to, RTLD_NOW | RTLD_GLOBAL, remote_open);
#endif
        }

        // stage 4: cleanup
        {
            // wait for injection
            std::this_thread::sleep_for(std::chrono::seconds(1));

            // remove the temporary copy
            mount(nullptr, "/system", nullptr, MS_MGC_VAL | MS_REMOUNT, "");
            remove(copy_path.data());
            mount(nullptr, "/system", nullptr, MS_MGC_VAL | MS_RDONLY | MS_REMOUNT, "");

            // unmap memory
            intptr_t remote_munmap = find_remote_function((intptr_t)::munmap);

            if (!remote_munmap)
                exit(-1);

            this->call_function(remote_munmap, 2, to, PAGE_SIZE);
        }
    }

    intptr_t allocate_memory()
    {
#if 1
        intptr_t remote_mmap = find_remote_function((intptr_t)::mmap);

        if (!remote_mmap)
            exit(-1);

        return this->call_function(remote_mmap, 6, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
#else
        intptr_t remote_calloc = find_remote_function((intptr_t)::calloc);

        if (!remote_calloc)
            exit(-1);

        return this->call_function(remote_calloc, 2, PAGE_SIZE, 0x1);
#endif
    }

    intptr_t find_remote_function(intptr_t address)
    {
        memory::map local_map, remote_map;

        memory::find_local_map(&local_map, address);
        memory::find_remote_map(&remote_map, local_map.path, m_pids.front());

        return address - local_map.address + remote_map.address;
    }

    void read_regs(uregs_t* regs)
    {
        if (!m_attached)
            return;

        struct iovec io;
        io.iov_base = regs;
        io.iov_len = sizeof(uregs_t);

        if (ptrace(PTRACE_GETREGSET, m_traceid, (void*)NT_PRSTATUS, &io) == -1)
            exit(-1);
    }

    void write_regs(uregs_t* regs)
    {
        if (!m_attached)
            exit(-1);

        struct iovec io;
        io.iov_base = regs;
        io.iov_len = sizeof(uregs_t);

        if (ptrace(PTRACE_SETREGSET, m_traceid, (void*)NT_PRSTATUS, &io) == -1)
            exit(-1);
    }

    void read_mem(intptr_t from, intptr_t to, size_t length)
    {
        struct iovec local_iov[1];
        struct iovec remote_iov[1];

        local_iov[0].iov_base = reinterpret_cast<void*>(to);
        local_iov[0].iov_len = length;

        remote_iov[0].iov_base = reinterpret_cast<void*>(from);
        remote_iov[0].iov_len = length;

        if (process_vm_readv(m_traceid, local_iov, 1, remote_iov, 1, 0) == -1)
            exit(-1);
    }

    void write_mem(intptr_t from, intptr_t to, size_t length)
    {
        struct iovec local_iov[1];
        struct iovec remote_iov[1];

        local_iov[0].iov_base = reinterpret_cast<void*>(from);
        local_iov[0].iov_len = length;

        remote_iov[0].iov_base = reinterpret_cast<void*>(to);
        remote_iov[0].iov_len = length;

        if (process_vm_writev(m_traceid, local_iov, 1, remote_iov, 1, 0) == -1)
            exit(-1);
    }

    uword_t call_syscall(uword_t syscall, size_t nargs, ...)
    {
        auto write_mem_trampoline = [&](auto a, auto b, auto c) { this->write_mem(a, b, c); };

        uregs_t regs = {}, regs_backup = {};

        this->read_regs(&regs);

        regs_backup = regs;

        regs::write_lr(&regs, 0x0, write_mem_trampoline);
        regs::write_syscall(&regs, syscall);

        va_list vargs;
        va_start(vargs, nargs);
        regs::write_param(&regs, nargs, vargs, write_mem_trampoline);
        va_end(vargs);

        this->write_regs(&regs);

        if (ptrace(PTRACE_CONT, m_traceid, nullptr, nullptr) == -1)
            exit(-1);

        waitpid(m_traceid, nullptr, WUNTRACED);

        this->read_regs(&regs);
        this->write_regs(&regs_backup);

        return regs::read_retval(regs);
    }

    uword_t call_function(intptr_t address, size_t nargs, ...)
    {
        auto write_mem_trampoline = [&](auto a, auto b, auto c) { this->write_mem(a, b, c); };

        uregs_t regs = {}, regs_backup = {};

        this->read_regs(&regs);

        regs_backup = regs;

        regs::write_lr(&regs, 0x0, write_mem_trampoline);
        regs::write_pc(&regs, address);

        va_list vargs;
        va_start(vargs, nargs);
        regs::write_param(&regs, nargs, vargs, write_mem_trampoline);
        va_end(vargs);

        this->write_regs(&regs);

        if (ptrace(PTRACE_CONT, m_traceid, nullptr, nullptr) == -1)
            exit(-1);

        waitpid(m_traceid, nullptr, WUNTRACED);

        this->read_regs(&regs);
        this->write_regs(&regs_backup);

        return regs::read_retval(regs);
    }

private:
    std::mutex m_mutex;
    std::string m_pname;
    std::vector<pid_t> m_pids;

    bool m_attached = false;
    pid_t m_traceid = 0;
};
