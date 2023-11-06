#include <windows.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <psapi.h>

/*
 * memory format
 * 0x00:  ??
 * 0x04:  Memory buffer
 * 0x08:  Buffer size
 * 0x0C:  ??
 * 0x10:  ??
 * 0x14:  Lower memory bound
 * 0x18:  Upper memory bound
*/
struct memory_region {
    uint8_t unk0[4];
    uint32_t buf_addr;
    uint32_t buf_size;
    uint8_t unk1[8];
    uint32_t lower_mem_bound;
    uint32_t upper_mem_bound;
    uint8_t unk2[4];
};

HMODULE getModule(HANDLE proc, char *name) {
    HMODULE mods[100];
    uint32_t cbNeeded;
    char modName[100];

    if (EnumProcessModules(proc, mods, sizeof(mods), &cbNeeded)) {
        for (int x = 0; x < (cbNeeded / sizeof(HMODULE)); x++) {
            GetModuleBaseNameA(proc, mods[x], modName, sizeof(modName));
            if (strcmp(name, modName) == 0) {
                return mods[x];
            }
        }
    }

    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <ROM Path> <Emulator PID>", argv[0]);
        return -1;
    }

    FILE *rom_file = fopen(argv[1], "rb");
    if (rom_file == NULL) {
        perror("Error opening ROM");
        return -1;
    }

    fseek(rom_file, 0, SEEK_END);
    long file_size = ftell(rom_file);
    fseek(rom_file, 0, SEEK_SET);

    uint8_t *rom_data = (uint8_t *)malloc(file_size);
    if (rom_data == NULL) {
        perror("Error allocating memory");
        fclose(rom_file);
        return -1;
    }

    size_t bytes_read = fread(rom_data, 1, file_size, rom_file);
    if (bytes_read != file_size) {
        perror("Error reading file");
        free(rom_data);
        fclose(rom_file);
        return -1;
    }

    // Get handle on the emulator
    uint32_t pid;
    sscanf(argv[2], "%" SCNd32, &pid);

    HANDLE proc = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            false, pid
    );

    if (proc == NULL) {
        printf("Failed to open handle: 0x%lx\n", GetLastError());
        return -1;
    }

    // Get SimU8.dll base address
    HMODULE SimU8_mod = getModule(proc, "SimU8.dll");
    if (SimU8_mod == NULL) {
        printf("Failed to get handle for SimU8.dll\n");
        return -1;
    }

    MODULEINFO modinfo;
    if (GetModuleInformation(proc, SimU8_mod, &modinfo, sizeof(modinfo)) == 0) {
        printf("Failed to get module info for SimU8.dll\n");
        return -1;
    }
    uint32_t SimU8_base_addr = (uint32_t) modinfo.lpBaseOfDll;

    // For version 1.11.100.0: 0x282C0
    // For version 1.15.200.0: 0x392AC
    // For version 2.0.100.0: 0x16CE20
    // For version 2.10.1.0: 0x16BE28
    uint32_t SimU8_state_offsets[4] = {0x282C0, 0x392AC, 0x16CE20, 0x16BE28};
    uint8_t buffer[0xFF];
    struct memory_region *rom_seg0;
    struct memory_region *rom_seg1;

    if (ReadProcessMemory(proc, (LPCVOID) (SimU8_base_addr + SimU8_state_offsets[3]), buffer, 0xFF, NULL) == 0) {
        printf("Failed to read memory: 0x%lx\n", GetLastError());
        return -1;
    }

    // ROM Segment 0 +0x2C
    // ROM Segment 1 +0x64
    rom_seg0 = (struct memory_region *) (buffer + 0x2C);
    rom_seg1 = (struct memory_region *) (buffer + 0x64);

    // Write segment 0 to memory
    if (WriteProcessMemory(proc, (LPVOID) rom_seg0->buf_addr, rom_data, rom_seg0->buf_size, NULL) == 0){
        printf("Write Segment 0 failed, 0x%lx\n", GetLastError());
        return -1;
    }
    // Write segment N to memory
    if (WriteProcessMemory(proc, (LPVOID) rom_seg1->buf_addr, rom_data + rom_seg0->buf_size, file_size - rom_seg0->buf_size, NULL)==0){
        printf("Write Segment N failed, 0x%lx\n", GetLastError());
        return -1;
    }

    printf("Done!\n");

    return 0;
}