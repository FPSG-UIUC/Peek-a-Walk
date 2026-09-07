#include "../util/util.h"
#include <sys/mman.h>

/* Gen macros */
#define PAGESIZE (4096)
#define TRIALS 10000

typedef struct node {
    uint64_t data;
    struct node *next; 
} node_t;

node_t *create_node(void) {
    node_t *cur = malloc(sizeof(node_t)); 
    cur->data = rand(); 
    cur->next = NULL;

    // trying to randomize node placement  
    int guard_size = rand() % 2000; 
    char *guard_page = malloc(guard_size); 
    for(int i = 0; i < guard_size; i++) 
        guard_page[i] = rand() % 256; 

    return (node_t *)((uint64_t)cur + ((uint64_t)guard_page & MSB_MASK));

}

uint64_t access_ll(node_t *head, uint64_t size, uint64_t consumer_load_bit, uint64_t __trash) {
    asm volatile(    
        "xor %%r12, %%r12\n"
        "xor %%r13, %%r13\n"
        "xor %%rbx, %%rbx\n"
        "mov %1, %%r11\n"

        "1:\n"
        "mov 8(%%r11), %%rax\n"  // fetch the next
        "cmp $1, %4\n"
        "jne 2f\n"
        "mfence\n" // spec barrier 
        "or (%%rax), %0\n"  // the random data
        "mov %%rax, %%r11\n" // set up the current pointer 

        // "mfence\n"
        // "or (%%r11), %0\n" // the random data 
        // "mov 8(%%r11), %%r11\n" // fetch the next and update 

        "2:\n"
        "add $1, %%r13\n" // size
        "cmp %3, %%r13\n"

        "jl 1b\n"
        : "=r" (__trash)
        : "r" (head), "0" (__trash), "r" (size), "r" (consumer_load_bit)
        : "cc", "r11", "r12", "r13", "rax", "rbx"
    );
    return __trash & MSB_MASK;
} 

int main(int argc, char **argv) {
    
    /* Grab arguments */
    if(argc != 3) {
        fprintf(stderr, "Error Usage: ./ll.out <training size> <test ptr offset>\n");
        exit(1);
    }
    uint64_t training_size = atoi(argv[1]);
    uint64_t test_ptr_offset = atoi(argv[2]);

    /* Init Ourselves */
    uint64_t __trash = 0; 
    pin_cpu(5);
    __trash = c_sleep(3000, __trash);
    _mm_mfence();

    /* Construct linked list */
    node_t *head = create_node(); 
    node_t *tail = head; 
    for(int i = 1; i < training_size; i++) {
        // create new node 
        node_t *cur = create_node(); 

        // append
        tail->next = cur; 
        tail = cur; 
    }

    // construct ptr_under_test 
    for(int i = 0; i <= test_ptr_offset; i++) {
        node_t *cur = create_node(); 

        // append 
        tail->next = cur;
        tail = cur; 
    }
    node_t *ptr_under_test = tail; 

    // conduct trials here 
     /* Main loop */
    uint64_t times[TRIALS] = {0}; 
    // for(int i = 0; i < TRIALS * 2; i++) {
    for(int i = 0; i < TRIALS; i++) {
        
        /* Kill the DMP */
        __trash = access_ll(head, 20, 0, __trash);
        _mm_mfence(); 
        
        /* flush the training aop */
        node_t *all_nodes [training_size + test_ptr_offset + 1]; 
        node_t *cur = head; 
        for(int j = 0; j < training_size + test_ptr_offset + 1; j++) {
            all_nodes[j] = cur; 
            cur = cur->next; 
        }
        for(int j = 0; j < training_size + test_ptr_offset + 1; j++)
            __trash = clflush(all_nodes[j], __trash); 
        // TODO zero out the all_nodes array? 
        _mm_mfence();

        /* flush ptr_under_test */
        __trash = clflush(ptr_under_test, __trash);
        _mm_mfence(); 

        /* training */
        __trash = access_ll(head, training_size, 1, __trash);
        _mm_mfence(); 

        /* give DMP time to catch up */
        __trash = c_sleep(200, __trash);

        /* time access for atck OR ensure no hits in base */ 
        uint64_t trial_access_time = time_access(ptr_under_test, __trash);
        // if (i % 2)
        //     times[i/2] = trial_access_time;
        // else 
        //     assert(trial_access_time > 100 && "Base mode registered a hit of the ptr_under_test!");
        times[i] = trial_access_time;
    }

    /* output */ 
    for(int i = 0 ; i < TRIALS; i++)
        fprintf(stderr, "%lu ", times[i]); 
    fprintf(stderr, "\n");

    return 0; 
}