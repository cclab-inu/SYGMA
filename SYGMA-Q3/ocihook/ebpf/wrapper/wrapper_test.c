#define main sygma_wrapper_program_main
#include "wrapper.c"
#undef main

#include <assert.h>

int main(void) {
    enum seccomp_routing_mode routing;

    assert(parse_seccomp_routing(NULL, &routing) == 0);
    assert(routing == SECCOMP_ROUTING_SELECTIVE);
    assert(parse_seccomp_routing("", &routing) == 0);
    assert(routing == SECCOMP_ROUTING_SELECTIVE);
    assert(parse_seccomp_routing(SYGMA_SECCOMP_ROUTING_SELECTIVE, &routing) == 0);
    assert(routing == SECCOMP_ROUTING_SELECTIVE);
    assert(parse_seccomp_routing(SYGMA_SECCOMP_ROUTING_ALL_TRACE, &routing) == 0);
    assert(routing == SECCOMP_ROUTING_ALL_TRACE);
    assert(parse_seccomp_routing("trace", &routing) == -1);
    assert(parse_seccomp_routing(SYGMA_SECCOMP_ROUTING_ALL_TRACE, NULL) == -1);

    assert(SELECTIVE_SECCOMP_FILTER_INSTRUCTION_COUNT == 300);
    assert(ALL_TRACE_SECCOMP_FILTER_INSTRUCTION_COUNT == 1);
    return 0;
}
