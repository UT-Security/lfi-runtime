#pragma once

#include <stdint.h>

#define MAXCALLBACKS 4096

#ifndef LAST_CALLBACK_KEY
// A CallbackEntry is what gets inserted into the sandbox when a new callback
// is registered. It consists of 16 bytes of code, which performs the callback
// transition to the host, along with the target function in the host to
// transfer to and the address of the trampoline. It must be 32 bytes to fit
// into a single bundle.
struct CallbackEntry {
    uint8_t code[16];
    _Atomic(uint64_t) target;
    _Atomic(uint64_t) trampoline;
};

_Static_assert(sizeof(struct CallbackEntry) == 32,
    "invalid callback entry size");
#else
// A CallbackEntry is what gets inserted into the sandbox when a new callback
// is registered. It consists of 40 bytes of code, which performs the callback
// transition to the host, along with the target function in the host to
// transfer to, the callback data and the address of the trampoline.
// The code is carefully crafted so that the beginning of the second bundle
// is a HLT byte to make it an invalid indirect jump target.
struct CallbackEntry {
    uint8_t code[40];
    _Atomic(uint64_t) target;
    _Atomic(uint64_t) key;
    _Atomic(uint64_t) trampoline;
};

_Static_assert(sizeof(struct CallbackEntry) == 64,
    "invalid callback entry size");
#endif

struct CallbackInfo {
    struct CallbackEntry *cbentries_alias;
    struct CallbackEntry *cbentries_box;
};

#define CALLBACK_ENTRIES_SIZE MAXCALLBACKS * sizeof(struct CallbackEntry)
