#if defined(HAVE_MEMFD_CREATE)
#define _GNU_SOURCE
#endif

#include "core.h"

#include <assert.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(HAVE_MEMFD_CREATE) && defined(HAVE_SYS_MEMFD_CREATE)
#include <sys/syscall.h>
int
memfd_create(const char *name, unsigned flags)
{
    return syscall(SYS_memfd_create, name, flags);
}
#endif

#ifndef LAST_CALLBACK_KEY
// The callback entry code loads the target into %r10 and then jumps to the
// trampoline address stored in the callback.
static uint8_t cbentry_code[16] = {
    // clang-format off
    0x4c, 0x8b, 0x15, 0x09, 0x00, 0x00, 0x00, // mov    0x9(%rip),%r10
    0xff, 0x25, 0x0b, 0x00, 0x00, 0x00,       // jmp    *0xb(%rip)
    0x0f, 0x01f, 0x00,                        // nop
    // clang-format on
};
#else
static uint8_t cbentry_code[40] = {
    0x4c, 0x8b, 0x15, 0x21, 0x00, 0x00, 0x00, // mov    33(%rip), %r10 - load target into %r10
    0x48, 0x8b, 0x05, 0x22, 0x00, 0x00, 0x00, // mov    34(%rip), %rax - load key into %rax
    0xff, 0x25, 0x24, 0x00, 0x00, 0x00,       // jmp    *36(%rip)      - jump to trampoline

    // NOP Pad out the remaining 12-bytes of the bundle.
    0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x90,

    // HLT to start the next bundle so it
    // cant be jumped to.
    0xf4,

    // NOP Pad out the remaining 7-bytes
    // before the 24-bytes of metadata.
    0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
};
#endif

extern void
lfi_callback(void);

extern void
lfi_callback_struct(void);

extern void
lfi_callback_stack_args(void);

static ssize_t
cbfreeslot(struct LFIBox *box)
{
    for (ssize_t i = 0; i < MAXCALLBACKS; i++) {
        if (!box->callbacks[i])
            return i;
    }
    return -1;
}

static ssize_t
cbfind(struct LFIBox *box, void *fn)
{
    for (size_t i = 0; i < MAXCALLBACKS; i++) {
        if (box->callbacks[i] == fn)
            return i;
    }
    return -1;
}

static bool
init_cb(struct LFIBox *box)
{
    int fd = memfd_create("", 0);
    if (fd < 0)
        return false;
    size_t size = MAXCALLBACKS * sizeof(struct CallbackEntry);
    int r = ftruncate(fd, size);
    if (r < 0)
        goto err;
    // Map callback entries outside the sandbox as read/write.
    void *aliasmap = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
        0);
    if (aliasmap == (void *) -1)
        goto err;
    box->cbinfo.cbentries_alias = (struct CallbackEntry *) aliasmap;
    // Fill in the code for each entry.
    for (size_t i = 0; i < MAXCALLBACKS; i++) {
        memcpy(&box->cbinfo.cbentries_alias[i].code, &cbentry_code[0],
            sizeof(box->cbinfo.cbentries_alias[i].code));
    }
    // Share the mapping inside the sandbox as read/exec. This mapping is
    // unverified because it contains specific trampoline sequences that the
    // verifier cannot validate.
    lfiptr boxmap = lfi_box_mapany_noverify(box, size,
        LFI_PROT_READ | LFI_PROT_EXEC, LFI_MAP_SHARED, fd, 0);
    if (boxmap == (lfiptr) -1)
        goto err1;
    box->cbinfo.cbentries_box = (struct CallbackEntry *) boxmap;

    close(fd);
    return true;
err1:
    munmap(aliasmap, size);
err:
    close(fd);
    return false;
}

static void *
register_cb(struct LFIBox *box, void* key, void *fn, uint64_t lfi_callback_fn)
{
    if (!box->cbinfo.cbentries_box) {
        if (!init_cb(box)) {
            LOG(box->engine, "error: failed to initialize callbacks");
            return NULL;
        }
    }

    assert(key);
    assert(fn);

    ssize_t slot = cbfind(box, key);
    if (slot != -1)
        return &box->cbinfo.cbentries_box[slot].code[0];

    slot = cbfreeslot(box);
    if (slot == -1)
        return NULL;

    // Write 'fn' into the 'target' field for the chosen slot.
    atomic_store_explicit(&box->cbinfo.cbentries_alias[slot].target,
        (uint64_t) fn, memory_order_seq_cst);
#ifdef LAST_CALLBACK_KEY
    // Write key into the 'key' field for the chosen slot.
    atomic_store_explicit(&box->cbinfo.cbentries_alias[slot].key,
        (uint64_t) key, memory_order_seq_cst);
#endif
    // Write the trampoline into the 'trampoline' field for the chosen slot
    atomic_store_explicit(&box->cbinfo.cbentries_alias[slot].trampoline,
        (uint64_t) lfi_callback_fn, memory_order_seq_cst);

    // Mark the slot as allocated.
    box->callbacks[slot] = key;

    return &box->cbinfo.cbentries_box[slot].code[0];
}

EXPORT void *
lfi_box_register_cb_key(struct LFIBox *box, void *key, void *fn,
    size_t stack_args)
{
#ifdef LAST_CALLBACK_KEY
    return register_cb(box, key, fn,
        stack_args == 0 ? (uint64_t) lfi_callback :
                          (uint64_t) lfi_callback_stack_args);
#else
    return NULL;
#endif
}

EXPORT void *
lfi_box_register_cb_struct(struct LFIBox *box, void *fn)
{
    return register_cb(box, fn, fn, (uint64_t) lfi_callback_struct);
}

EXPORT void *
lfi_box_register_cb(struct LFIBox *box, void *fn)
{
    return register_cb(box, fn, fn, (uint64_t) lfi_callback);
}

EXPORT void
lfi_box_unregister_cb(struct LFIBox *box, void *fn)
{
    ssize_t slot = cbfind(box, fn);
    if (slot == -1)
        return;
    box->callbacks[slot] = NULL;
    atomic_store_explicit(&box->cbinfo.cbentries_alias[slot].target, 0,
        memory_order_seq_cst);
#ifdef LAST_CALLBACK_KEY
    atomic_store_explicit(&box->cbinfo.cbentries_alias[slot].key, 0,
        memory_order_seq_cst);
#endif
    atomic_store_explicit(&box->cbinfo.cbentries_alias[slot].trampoline, 0,
        memory_order_seq_cst);
}

void
lfi_box_cb_free(struct LFIBox *box)
{
    if (box->cbinfo.cbentries_alias)
        munmap(box->cbinfo.cbentries_alias,
            MAXCALLBACKS * sizeof(struct CallbackEntry));
}

EXPORT void *
lfi_box_lookup_cb(struct LFIBox *box, void* cb)
{
    assert(cb);

    if (cb < (void *) &box->cbinfo.cbentries_box[0] ||
        cb >= (void *) ((uint8_t *) &box->cbinfo.cbentries_box[0] +
                  CALLBACK_ENTRIES_SIZE)) {
        return NULL;
    }

    size_t slot = ((uint8_t *) cb - (uint8_t *) &box->cbinfo.cbentries_box[0]) /
        sizeof(struct CallbackEntry);

    assert(slot < MAXCALLBACKS);
    assert(&box->cbinfo.cbentries_box[slot].code[0] == cb);

    return box->callbacks[slot];
}
