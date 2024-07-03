/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#define _POSIX_C_SOURCE 200809L

#include "RandHash.h"
#include "Hash.h"
#include "Buf.h"
#include "CryptoCycle.h"
#include "Work.h"
#include "PTime.h"
#include "Announce.h"
#include "packetcrypt/PacketCrypt.h"
#include "packetcrypt/AnnMiner.h"
#include "Conf.h"
#include "Util.h"
#include "packetcrypt/Validate.h"
#include "ValidateCtx.h"
#include "item_flags.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>

long timediff(clock_t t1, clock_t t2) {
    long elapsed;
    elapsed = ((double)t2 - t1) / CLOCKS_PER_SEC * 1000;
    return elapsed;
}

typedef struct {
    PacketCrypt_AnnounceHdr_t annHdr;
    Buf64_t hash;
} HeaderAndHash_t;

typedef struct {
    Buf32_t parentBlockHash;
    char* content;
    HeaderAndHash_t hah;
} Job_t;

typedef struct Worker_s Worker_t;
struct AnnMiner_s {
    int numWorkers;
    Worker_t* workers;

    HeaderAndHash_t hah;

    bool active;
    uint32_t minerId;

    void* callback_ctx;
    AnnMiner_Callback ann_found;

    struct timeval startTime;

    pthread_mutex_t lock;
    pthread_cond_t cond;
};

enum ThreadState {
    ThreadState_STOPPED,
    ThreadState_RUNNING,
    ThreadState_SHUTDOWN
};

struct Worker_s {
    //Job_t* activeJob;
    Job_t job;

    AnnMiner_t* ctx;
    pthread_t thread;

    uint32_t workerNum;

    int softNonce;
    int softNonceMax;

    _Atomic uintptr_t cycles;
    _Atomic enum ThreadState reqState;
    _Atomic enum ThreadState workerState;
};

static CryptoCycle_Item_t PrimaryTable[Announce_TABLE_SZ];

static inline void setRequestedState(AnnMiner_t* ctx, Worker_t* w, enum ThreadState ts) {
    (void)(ctx);
    w->reqState = ts;
}
static inline enum ThreadState getRequestedState(Worker_t* w) {
    return w->reqState;
}
static inline void setState(Worker_t* w, enum ThreadState ts) {
    w->workerState = ts;
}
static inline enum ThreadState getState(AnnMiner_t* ctx, Worker_t* w) {
    (void)(ctx);
    return w->workerState;
}

static AnnMiner_t* allocCtx(int numWorkers)
{
    AnnMiner_t* ctx = calloc(sizeof(AnnMiner_t), 1);
    assert(ctx);
    assert(!pthread_mutex_init(&ctx->lock, NULL));
    assert(!pthread_cond_init(&ctx->cond, NULL));

    ctx->numWorkers = numWorkers;
    ctx->workers = calloc(sizeof(Worker_t), numWorkers);
    assert(ctx->workers);
    for (int i = 0; i < numWorkers; i++) {
        ctx->workers[i].ctx = ctx;
    }
    return ctx;
}
static void freeCtx(AnnMiner_t* ctx)
{
    assert(!pthread_cond_destroy(&ctx->cond));
    assert(!pthread_mutex_destroy(&ctx->lock));
    free(ctx->workers);
    free(ctx);
}

__attribute__((unused)) static int populatePrimaryTableJIT(Buf64_t* seed) {
    printf("populate primary (jit)\n");
    PacketCrypt_ValidateCtx_t *vctx = ValidateCtx_create();

    if (Announce_createProg(vctx, &seed->thirtytwos[0])) {
        ValidateCtx_destroy(vctx);
        return -1;
    }

    rh_jit_program_t *program = rh_generate_program(vctx->progbuf, vctx->progLen);

    for (int i = 0; i < Announce_TABLE_SZ; i++) {
        rh_make_item(i, &PrimaryTable[i], vctx, &seed->thirtytwos[1], program);
    }

    rh_free_program(program);

    ValidateCtx_destroy(vctx);

    return 0;
}

// -1 means try again
static int populatePrimaryTable(Buf64_t* seed) {
    #ifdef JIT_ENABLED
    return populatePrimaryTableJIT(seed);
    #endif
    printf("populate primary (legacy)\n");
    PacketCrypt_ValidateCtx_t *vctx = ValidateCtx_create();
    if (Announce_createProg(vctx, &seed->thirtytwos[0])) {
        ValidateCtx_destroy(vctx);
        return -1;
    }
    for (int i = 0; i < Announce_TABLE_SZ; i++) {
        if (Announce_mkitem2(i, &PrimaryTable[i], &seed->thirtytwos[1], vctx)) {
            ValidateCtx_destroy(vctx);
            return -1;
        }
    }
    ValidateCtx_destroy(vctx);
    return 0;
}

#define HASHES_PER_CYCLE 16

static bool checkStop(Worker_t* worker) {
    if (getRequestedState(worker) == ThreadState_RUNNING) {
        // This is checking a non-atomic memory address without synchronization
        // but if we don't read the most recent data, it doesn't matter, we'll
        // be back in 512 more cycles.
        return false;
    }
    pthread_mutex_lock(&worker->ctx->lock);
    for (;;) {
        enum ThreadState rts = getRequestedState(worker);
        if (rts != ThreadState_STOPPED) {
            setState(worker, rts);
            pthread_mutex_unlock(&worker->ctx->lock);
            if (rts == ThreadState_SHUTDOWN) {
                return true;
            }
            return false;
        }
        setState(worker, rts);
        pthread_cond_wait(&worker->ctx->cond, &worker->ctx->lock);
        worker->cycles = 0;
    }
}

inline void merkle_flatten_item_row(int depth, uint8_t* out, const uint8_t* table, int itemSz) {
    int odx = 0;
    for (int i = 0; i < (1 << depth); i++) {
        const uint8_t *item = &table[odx * itemSz];
        Hash_compress64(&out[odx * 64], item, itemSz);
        odx++;
    }
}

inline void merkle_build_up_to(int depth, uint8_t level, uint8_t* out) {
    int odx = 8192; // offset from item row hashes - hacky - this is only a
                    // proof-of-concept impl.
    int idx = 0;
    for (int d = depth; d >= level; d--) {
        for (int i = 0; i < (1 << d); i++) {
            if (d == depth && i == 0) { // if leaf 0 randomise it
                randombytes(out, 64);
            }
            Hash_compress64(&out[odx * 64], &out[idx * 64], 128);
            odx++;
            idx += 2;
        }
    }
    // printf("odx [%d] idx [%d]\n", odx, idx);
    // assert(odx == (1<<depth) * 2 - 1);
    // assert(idx == odx - 1);
}

inline void merkle_build_fake_branch(int depth, uint8_t level, uint8_t* out) {
    int odx = 8192; // offset from item row hashes - hacky - this is only a
                    // proof-of-concept impl.
    int idx = 0;
    for (int d = depth; d >= level; d--) {
        for (int i = 0; i < (1 << d); i++) {
            if (d == depth && i == 0) { // if leaf 0 randomise it
                randombytes(out, 64);
            }
            if (i < ((1 << d) / level))
                Hash_compress64(&out[odx * 64], &out[idx * 64], 128);
            odx++;
            idx += 2;
        }
    }
    // printf("odx [%d] idx [%d]\n", odx, idx);
    // assert(odx == (1<<depth) * 2 - 1);
    // assert(idx == odx - 1);
}

void merkle_build_to_root(int depth, uint8_t* out) {
    int odx = 16368; // hacky - this is only a proof-of-concept impl.
    int idx = 16352;
    for (int d = depth; d >= 0; d--) {
        for (int i = 0; i < (1 << d); i++) {
            Hash_compress64(&out[odx * 64], &out[idx * 64], 128);
            odx++;
            idx += 2;
        }
    }
    // assert(odx == (1 << depth) * 2 - 1);
    // assert(idx == odx - 1);
}

// #define TOTAL_HITS 10

static void* thread(void* vworker) {
    Worker_t* worker = vworker;
    Announce_Merkle merkle;
    Buf64_t annHash0; // hash(announce || parentBlockHash)
    Buf64_t annHash1; // hash(announce || merkleRoot)
    CryptoCycle_State_t state;
    CryptoCycle_Item_t item_1;
    CryptoCycle_Item_t item_n;
    Announce_t ann;
    bool rebuild = true;

    PacketCrypt_ValidateCtx_t *vctx = ValidateCtx_create();

    Item_Flags_t *item_cache_flags = item_flags_make(Announce_TABLE_SZ);
    CryptoCycle_Item_t *item_cache = (CryptoCycle_Item_t *)malloc(Announce_TABLE_SZ * sizeof(CryptoCycle_Item_t));

    for (;;) {
        if (checkStop(worker)) {
            item_flags_free(item_cache_flags);
            free(item_cache);
            ValidateCtx_destroy(vctx);
            printf("worker thread exit (check-stop)\n");
            return NULL;
        }

        item_flags_reset(item_cache_flags);

        if (Buf_OBJCMP(&worker->job.hah.annHdr, &worker->ctx->hah.annHdr)) {
            rebuild = true;
        }

        Buf_OBJCPY(&worker->job.hah, &worker->ctx->hah);
        Hash_COMPRESS64_OBJ(&annHash0, &worker->job.hah);

        if (rebuild) {
            rebuild = false;
            // printf("rebuild merkle...\n");
            merkle_flatten_item_row(13, &merkle, (const uint8_t *)PrimaryTable, sizeof *PrimaryTable);
            merkle_build_up_to(12, 4, &merkle);
        } else {
            printf("soft nonce range exhausted - fake a new hard nonce round...\n");
            // rebuild just fake branch then up to root
            merkle_build_fake_branch(12, 4, &merkle); // fast rebuild
        }

        merkle_build_to_root(4, &merkle);

        Buf64_t *root = Announce_Merkle_root(&merkle);
        // Buf_OBJCPY(&worker->job.parentBlockHash, &worker->job.hah.hash.thirtytwos[0]);
        Buf_OBJCPY(&worker->job.hah.hash, root);
        Hash_COMPRESS64_OBJ(&annHash1, &worker->job.hah);

        Buf64_t cycle_program_seed[2];
        Buf_OBJCPY(&cycle_program_seed[0], root);
        Buf_OBJCPY(&cycle_program_seed[1], &annHash0);
        Hash_COMPRESS64_OBJ(&cycle_program_seed[0], &cycle_program_seed);

        Announce_createProg(vctx, &cycle_program_seed[0].thirtytwos[0]);

        #ifdef JIT_ENABLED
        rh_jit_program_t *program = rh_generate_program(vctx->progbuf, vctx->progLen);
        #endif

        // dummy cycle init to get cycle #1 item number (always same)  NOTE:  this is only worth doing if you plan to make n items on-the-fly
        CryptoCycle_init(&state, &annHash1.thirtytwos[0], 0);
        int itemNo = (CryptoCycle_getItemNo(&state) % Announce_TABLE_SZ);
        if (itemNo == 0) { // skip as its a fake leaf
            continue;
        }
        #ifdef JIT_ENABLED
        rh_make_item(itemNo, &item_1, vctx, &cycle_program_seed[0].thirtytwos[1], program);
        #else
        Announce_mkitem2(itemNo, &item_1, &cycle_program_seed[0].thirtytwos[1], vctx);
        #endif

        // perform search for anns across nonce range
        uint32_t nonce_max = 0; // miner->nonce_max;
        if (nonce_max == 0)
            nonce_max = Util_annSoftNonceMax(worker->job.hah.annHdr.workBits);
        // uint32_t hits = 0;

        for (uint32_t nonce = 0; nonce < nonce_max; nonce++) {
            if (getRequestedState(worker) != ThreadState_RUNNING) {
                break;
            }
            // if (hits > TOTAL_HITS)
            //   break;
            CryptoCycle_init(&state, &annHash1.thirtytwos[0], nonce);

            if (!CryptoCycle_update(&state, &item_1)) {
                item_flags_free(item_cache_flags);
                free(item_cache);
                #ifdef JIT_ENABLED
                rh_free_program(program);
                #endif
                ValidateCtx_destroy(vctx);
                printf("fail @1\n");
                return NULL;
            }

            bool good = true;

            for (uint8_t cycle = 0; cycle < 3; cycle++) {
                itemNo = (CryptoCycle_getItemNo(&state) % Announce_TABLE_SZ);
                if (itemNo == 0) { // skip as its a fake leaf
                    good = false;
                    break;
                }
                if (item_flags_read(item_cache_flags, itemNo) == 1) {
                    memcpy(&item_n, item_cache + itemNo, sizeof(CryptoCycle_Item_t));
                } else {
                    #ifdef JIT_ENABLED
                    rh_make_item(itemNo, &item_n, vctx, &cycle_program_seed[0].thirtytwos[1], program);
                    #else
                    Announce_mkitem2(itemNo, &item_n, &cycle_program_seed[0].thirtytwos[1], vctx);
                    #endif

                    memcpy(item_cache + itemNo, &item_n, sizeof(CryptoCycle_Item_t));
                    item_flags_set(item_cache_flags, itemNo, 1);
                }
                if (!CryptoCycle_update(&state, &item_n)) {
                    item_flags_free(item_cache_flags);
                    free(item_cache);
                    #ifdef JIT_ENABLED
                    rh_free_program(program);
                    #endif
                    ValidateCtx_destroy(vctx);
                    printf("fail @2\n");
                    return NULL;
                }
            }

            if (good) {
                CryptoCycle_final(&state);

                if (Work_check(state.bytes, worker->job.hah.annHdr.workBits)) {
                    // printf("valid ann found!  soft nonce [%d]\n", nonce);
                    Buf_OBJCPY(&ann.hdr, &worker->job.hah.annHdr);
                    Buf_OBJCPY_LDST(ann.hdr.softNonce, &nonce);
                    Announce_Merkle_getBranch(&ann.merkleProof, itemNo, &merkle);
                    Buf_OBJSET(ann.lastAnnPfx, 0);
                    Announce_crypt(&ann, &state);

                    worker->ctx->ann_found(worker->ctx->callback_ctx, (uint8_t *)&ann);
                    // hits++;
                }
            }
        }

        #ifdef JIT_ENABLED
        rh_free_program(program);
        #endif
    }
}

static bool threadsStopped(AnnMiner_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        enum ThreadState ts = getState(ctx, &ctx->workers[i]);
        if (ts == ThreadState_RUNNING) { return false; }
    }
    return true;
}

static void stopThreads(AnnMiner_t* ctx) {
    printf("stop threads called\n");
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_STOPPED);
    }
}

void AnnMiner_start(AnnMiner_t* ctx, AnnMiner_Request_t* req, int version) {
    stopThreads(ctx);
    while (!threadsStopped(ctx)) { Time_nsleep(100000); }

    HeaderAndHash_t hah;
    Buf_OBJSET(&hah, 0);
    hah.annHdr.version = version;
    hah.annHdr.hardNonce = 109; //hardnonce bypass - value no longer matters
    hah.annHdr.workBits = req->workTarget;
    hah.annHdr.parentBlockHeight = req->parentBlockHeight;
    hah.annHdr.contentType = req->contentType;
    hah.annHdr.contentLength = req->contentLen;
    Buf_OBJCPY(hah.annHdr.signingKey, req->signingKey);

    Buf_OBJCPY(&hah.hash.thirtytwos[0], req->parentBlockHash);

    // we only need one of these table for all our workers! :D
    Buf64_t annHash0; // hash(announce || parentBlockHash)
    Hash_COMPRESS64_OBJ(&annHash0, &hah);

    populatePrimaryTable(&annHash0); //only one full 1<<13 populate needed for ALL threads/jobs (per block)

    Buf_OBJCPY(&ctx->hah, &hah);

    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_RUNNING);
    }
    gettimeofday(&ctx->startTime, NULL);
    pthread_cond_broadcast(&ctx->cond);

    ctx->active = true;
    return;
}

AnnMiner_t* AnnMiner_create(
    uint32_t minerId,
    int threads,
    void* callback_ctx,
    AnnMiner_Callback ann_found)
{
    assert(threads);
    AnnMiner_t* ctx = allocCtx(threads);
    ctx->minerId = minerId;
    ctx->ann_found = ann_found;
    ctx->callback_ctx = callback_ctx;

    for (int i = 0; i < threads; i++) {
        ctx->workers[i].workerNum = i;
        assert(!pthread_create(&ctx->workers[i].thread, NULL, thread, &ctx->workers[i]));
    }
    return ctx;
}

void AnnMiner_stop(AnnMiner_t* ctx)
{
    ctx->active = false;
    stopThreads(ctx);
    while (!threadsStopped(ctx)) { Time_nsleep(100000); }
}

void AnnMiner_free(AnnMiner_t* ctx)
{
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_SHUTDOWN);
    }
    pthread_cond_broadcast(&ctx->cond);
    while (!threadsStopped(ctx)) { Time_nsleep(100000); }

    for (int i = 0; i < ctx->numWorkers; i++) {
        assert(!pthread_join(ctx->workers[i].thread, NULL));
    }

    freeCtx(ctx);
}

double AnnMiner_hashesPerSecond(AnnMiner_t* ctx)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct timeval tv0 = ctx->startTime;
    uint64_t micros = ((uint64_t)tv.tv_sec - tv0.tv_sec) * 1000000ull + tv.tv_usec - tv0.tv_usec;
    ctx->startTime = tv;

    uint64_t totalCycles = 0;
    for (int i = 0; i < ctx->numWorkers; i++) {
        totalCycles += ctx->workers[i].cycles;
        ctx->workers[i].cycles = 0;
    }
    double hashes = (double) (totalCycles * HASHES_PER_CYCLE); // total hashes done
    hashes /= (double) micros;
    hashes *= 1000000.0;
    return hashes;
}
