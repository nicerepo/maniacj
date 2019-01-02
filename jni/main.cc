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
// main.cc
//
//===------------------------------------------------------------------------------------------===//

#include "process.h"

int
main(int argc, char** argv)
{
    if (argc != 3)
        return -1;

    Process process(argv[1]);

    if (process.rpid() == -1)
        return -1;

    process.attach();
    process.inject(argv[2]);
    process.detach();

    return 0;
}
