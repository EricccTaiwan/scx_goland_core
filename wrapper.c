#include "wrapper.h"

void *open_skel() {
    struct main_bpf *obj = NULL;
    obj =  main_bpf__open_and_load();
    main_bpf__create_skeleton(obj);
    return obj;
}

void destroy_skel(void*skel) {
    main_bpf__destroy(skel);
}