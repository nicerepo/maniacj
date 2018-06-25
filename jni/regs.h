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
// regs.h: register manipulation abstraction layer
//
//===------------------------------------------------------------------------------------------===//

#pragma once

#include <functional>

#if defined(__LP64__)

#define process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)                      \
    syscall(270, pid, local_iov, liovcnt, remote_iov, riovcnt, flags)

#define process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)                     \
    syscall(271, pid, local_iov, liovcnt, remote_iov, riovcnt, flags)

#else

#define process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)                      \
    syscall(376, pid, local_iov, liovcnt, remote_iov, riovcnt, flags)

#define process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)                     \
    syscall(377, pid, local_iov, liovcnt, remote_iov, riovcnt, flags)

#endif

typedef struct uregs_struct {
#if defined(__aarch64__)
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;

#elif defined(__arm__)
    long uregs[18];

#elif defined(__x86_64__)
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
    unsigned long fs_base;
    unsigned long gs_base;
    unsigned long ds;
    unsigned long es;
    unsigned long fs;
    unsigned long gs;

#elif defined(__i386__)
    long ebx;
    long ecx;
    long edx;
    long esi;
    long edi;
    long ebp;
    long eax;
    int xds;
    int xes;
    int xfs;
    int xgs;
    long orig_eax;
    long eip;
    int xcs;
    long eflags;
    long esp;
    int xss;

#endif
} uregs_t;

#if defined(__LP64__)
typedef uint64_t uword_t;
#else
typedef uint32_t uword_t;
#endif

#define writemem_t const std::function<void(intptr_t, uword_t, size_t)>&

namespace regs {

//===----------------------------------------------------------------------===//
// ARM64 specific implementations
//===----------------------------------------------------------------------===//
#if defined(__aarch64__)

uword_t read_retval(const uregs_t& regs)
{
    return regs.regs[0];
}

uword_t read_sp(const uregs_t& regs)
{
    return regs.sp;
}

uword_t read_pc(const uregs_t& regs)
{
    return regs.pc;
}

void push(uregs_t* regs, uword_t stack, writemem_t write_mem)
{
    regs->sp -= sizeof(uword_t);
    write_mem(reinterpret_cast<intptr_t>(&stack), read_sp(*regs), sizeof(uword_t));
}

void pop(uregs_t* regs)
{
    regs->sp += sizeof(uword_t);
}

void write_pc(uregs_t* regs, intptr_t address)
{
    regs->pc = address;

    if (regs->pc & 1) {
        regs->pc &= (~1u);
        regs->pstate |= 0x00000020;
    } else {
        regs->pstate &= (~0x00000020);
    }
}

void write_lr(uregs_t* regs, intptr_t address, writemem_t write_mem)
{
    regs->regs[30] = address;
}

void write_syscall(uregs_t* regs, int n)
{
    regs->regs[8] = n;
}

void write_param(uregs_t* regs, size_t nargs, va_list args, writemem_t write_mem)
{
    for (int i = 0; i < nargs; ++i) {
        if (i < 8)
            regs->regs[i] = (uword_t)va_arg(args, uword_t);
        else
            push(regs, va_arg(args, uword_t), write_mem);
    }
}

//===----------------------------------------------------------------------===//
// ARM32 specific implementations
//===----------------------------------------------------------------------===//
#elif defined(__arm__)

uword_t read_retval(const uregs_t& regs)
{
    return regs.uregs[0];
}

uword_t read_sp(const uregs_t& regs)
{
    return regs.uregs[13];
}

uword_t read_pc(const uregs_t& regs)
{
    return regs.uregs[15];
}

void push(uregs_t* regs, uword_t stack, writemem_t write_mem)
{
    regs->uregs[13] -= sizeof(uword_t);
    write_mem(reinterpret_cast<intptr_t>(&stack), read_sp(*regs), sizeof(uword_t));
}

void pop(uregs_t* regs)
{
    regs->uregs[13] += sizeof(uword_t);
}

void write_pc(uregs_t* regs, intptr_t address)
{
    regs->uregs[15] = address;

    if (regs->uregs[15] & 1) {
        regs->uregs[15] &= (~1u);
        regs->uregs[16] |= PSR_T_BIT;
    } else {
        regs->uregs[16] &= (~PSR_T_BIT);
    }
}

void write_lr(uregs_t* regs, intptr_t address, writemem_t write_mem)
{
    regs->uregs[14] = address;
}

void write_syscall(uregs_t* regs, int n)
{
    regs->uregs[7] = n;
}

void write_param(uregs_t* regs, size_t nargs, va_list args, writemem_t write_mem)
{
    for (int i = 0; i < nargs; ++i) {
        if (i < 4)
            regs->uregs[i] = (uword_t)va_arg(args, uword_t);
        else
            push(regs, va_arg(args, uword_t), write_mem);
    }
}

//===----------------------------------------------------------------------===//
// x86_64 specific implementations
//===----------------------------------------------------------------------===//
#elif defined(__x86_64__)

uword_t read_retval(const uregs_t& regs)
{
    return regs.rax;
}

uword_t read_sp(const uregs_t& regs)
{
    return regs.rsp;
}

uword_t read_pc(const uregs_t& regs)
{
    return regs.rip;
}

void push(uregs_t* regs, uword_t stack, writemem_t write_mem)
{
    regs->rsp -= sizeof(uword_t);
    write_mem(reinterpret_cast<intptr_t>(&stack), read_sp(*regs), sizeof(uword_t));
}

void pop(uregs_t* regs)
{
    regs->rsp += sizeof(uword_t);
}

void write_pc(uregs_t* regs, intptr_t address)
{
    regs->rip = address;
}

void write_lr(uregs_t* regs, intptr_t address, writemem_t write_mem)
{
    push(regs, address, write_mem);
}

void write_syscall(uregs_t* regs, int n)
{
    regs->rax = n;
}

void write_param(uregs_t* regs, size_t nargs, va_list args, writemem_t write_mem)
{
    for (int i = 0; i < nargs; ++i) {
        switch (i) {
        case 0:
            regs->rcx = (uword_t)va_arg(args, uword_t);
            break;
        case 1:
            regs->rdx = (uword_t)va_arg(args, uword_t);
            break;
        case 2:
            regs->r8 = (uword_t)va_arg(args, uword_t);
            break;
        case 3:
            regs->r9 = (uword_t)va_arg(args, uword_t);
            break;
        default:
            push(regs, (uword_t)va_arg(args, uword_t), write_mem);
        }
    }
}

//===----------------------------------------------------------------------===//
// x86 specific implementations
//===----------------------------------------------------------------------===//
#elif defined(__i386__)

uword_t read_retval(const uregs_t& regs)
{
    return regs.eax;
}

uword_t read_sp(const uregs_t& regs)
{
    return regs.esp;
}

uword_t read_pc(const uregs_t& regs)
{
    return regs.eip;
}

void push(uregs_t* regs, uword_t stack, writemem_t write_mem)
{
    regs->esp -= sizeof(uword_t);
    write_mem(reinterpret_cast<intptr_t>(&stack), read_sp(*regs), sizeof(uword_t));
}

void pop(uregs_t* regs)
{
    regs->esp -= sizeof(uword_t);
}

void write_pc(uregs_t* regs, intptr_t address)
{
    regs->eip = address;
}

void write_lr(uregs_t* regs, intptr_t address, writemem_t write_mem)
{
    push(regs, address, write_mem);
}

void write_syscall(uregs_t* regs, int n)
{
    regs->eax = n;
}

void write_param(uregs_t* regs, size_t nargs, va_list args, writemem_t write_mem)
{
    for (int i = 0; i < nargs; ++i)
        push(regs, (uword_t)va_arg(args, uword_t), write_mem);
}

#endif
}

#undef writemem_t
