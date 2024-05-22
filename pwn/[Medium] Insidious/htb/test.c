#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

uint32_t prefetch_time(uint64_t addr);
uint32_t prefetch_time_multiple(uint64_t addr);

#define RANDOM_INVALID_ADDRESS (uint64_t)0xdeadbeef
#define LOOP_ITERATIONS 0x10

int main(){
    uint64_t map = (uint64_t)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0);
    *(int*)map = 123456;    // write something to the map so it's guarnteed to be backed by a physical map

    uint32_t prefetch_on_valid_map   = prefetch_time_multiple(map);
    uint32_t prefetch_on_invalid_map = prefetch_time_multiple(RANDOM_INVALID_ADDRESS);

    printf("prefetch_on_valid_map:%04d\n",  prefetch_on_valid_map);
    printf("prefetch_on_invalid_map:%04d\n",prefetch_on_invalid_map);
    printf("threshold:%04d\n",(uint32_t)(prefetch_on_valid_map+prefetch_on_invalid_map/2));
}

uint32_t prefetch_time_multiple(uint64_t addr){
    uint32_t sum=0;
    for (int i=0;i<LOOP_ITERATIONS;i++)
        sum+= prefetch_time(addr);
    return sum;
}

__attribute__((optimize("O3")))
uint32_t prefetch_time(uint64_t addr){
    asm volatile(    
        "rdtsc;"
        "mov esi,eax;"
        "lfence;"
        
        "prefetchnta     [%0];"
        "prefetcht2      [%0];"
        "prefetcht1      [%0];"
        "prefetcht0      [%0];"

        "lfence;"
        "rdtsc;"
        "sub eax,esi;"
        ::"r"(addr):"rsi","rax"
    );
}