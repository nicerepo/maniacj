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
// memory.h
//
//===------------------------------------------------------------------------------------------===//

#pragma once

namespace memory {

struct map {
    uintptr_t address;
    size_t size;
    std::string path;
};

void find_map(map* map, const std::string& path, pid_t pid)
{
    char line[256] = { 0 };

    if (pid)
        snprintf(line, sizeof(line), "/proc/%d/maps", pid);
    else
        snprintf(line, sizeof(line), "/proc/self/maps");

    FILE* fp = fopen(line, "r");

    if (!fp)
        exit(-1);

    char* saved_pointer = NULL;
    char* start_address = NULL;
    char* end_address = NULL;
    char* path_entry = NULL;

    while (fgets(line, sizeof(line), fp)) {
        start_address = strtok_r(line, "-", &saved_pointer);
        end_address = strtok_r(NULL, "\t ", &saved_pointer);

        strtok_r(NULL, "\t ", &saved_pointer); // "r-xp" field
        strtok_r(NULL, "\t ", &saved_pointer); // "0000000" field
        strtok_r(NULL, "\t ", &saved_pointer); // "01:02" field
        strtok_r(NULL, "\t ", &saved_pointer); // "133224" field

        path_entry = strtok_r(NULL, "\t ", &saved_pointer); // path field

        if (!path_entry)
            continue;

        // trim trailing whitespace
        char* end = path_entry + strlen(path_entry) - 1;
        while (end > path_entry && isspace(*end))
            --end;
        *(end + 1) = 0;

        if (strlen(path_entry) < path.length())
            continue;

        if (strncmp(end - path.length() + 1, path.data(), path.length()) == 0) {
            fclose(fp);
            map->address = strtoul(start_address, NULL, 16);
            map->size = strtoul(end_address, NULL, 16) - map->address;
            map->path = path_entry;
            return;
        }
    }

    map->address = 0;
    map->size = 0;
    map->path = "";

    fclose(fp);
}

void find_map(map* map, uintptr_t address, pid_t pid)
{
    char line[256] = { 0 };

    if (pid)
        snprintf(line, sizeof(line), "/proc/%d/maps", pid);
    else
        snprintf(line, sizeof(line), "/proc/self/maps");

    FILE* fp = fopen(line, "r");

    if (!fp)
        exit(-1);

    char* saved_pointer = NULL;
    char* start_address = NULL;
    char* end_address = NULL;
    char* path_entry = NULL;

    while (fgets(line, sizeof(line), fp)) {
        start_address = strtok_r(line, "-", &saved_pointer);
        end_address = strtok_r(NULL, "\t ", &saved_pointer);

        strtok_r(NULL, "\t ", &saved_pointer); // "r-xp" field
        strtok_r(NULL, "\t ", &saved_pointer); // "0000000" field
        strtok_r(NULL, "\t ", &saved_pointer); // "01:02" field
        strtok_r(NULL, "\t ", &saved_pointer); // "133224" field

        path_entry = strtok_r(NULL, "\t ", &saved_pointer); // path field

        if (!path_entry)
            continue;

        // trim trailing whitespace
        char* end = path_entry + strlen(path_entry) - 1;
        while (end > path_entry && isspace(*end))
            --end;
        *(end + 1) = 0;

        uintptr_t start_address_ptr = strtoul(start_address, NULL, 16);
        uintptr_t end_address_ptr = strtoul(end_address, NULL, 16);

        if (address > start_address_ptr && address < end_address_ptr) {
            fclose(fp);
            map->address = start_address_ptr;
            map->size = end_address_ptr - start_address_ptr;
            map->path = path_entry;
            return;
        }
    }

    map->address = 0;
    map->size = 0;
    map->path = "";

    fclose(fp);
}

void find_remote_map(map* map, const std::string& path, pid_t pid)
{
    find_map(map, path, pid);
}

void find_remote_map(map* map, uintptr_t address, pid_t pid)
{
    find_map(map, address, pid);
}

void find_local_map(map* map, const std::string& path)
{
    find_map(map, path, 0);
}

void find_local_map(map* map, uintptr_t address)
{
    find_map(map, address, 0);
}

}
