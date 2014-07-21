/* Copyright 2012, 2014 Jeff Trawick, http://emptyhammock.com/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DIAG_H
#define DIAG_H

#include "diagplat.h"

#if DIAG_PLATFORM_WINDOWS
#include <windows.h>
#include <dbghelp.h>
#else
#include <signal.h>
#endif

#if DIAG_PLATFORM_SOLARIS
#include <ucontext.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define DIAG_BTFIELDS_ALL          0xFFFFFFFF
#define DIAG_BTFIELDS_MODULE_PATH  0x00000001
#define DIAG_BTFIELDS_MODULE_NAME  0x00000002
#define DIAG_BTFIELDS_FUNCTION     0x00000004
#define DIAG_BTFIELDS_FN_OFFSET    0x00000008
#define DIAG_BTFIELDS_ADDRESS      0x00000010 

typedef struct {
    void *user_data;
    enum {DIAG_WRITE_FD, DIAG_CALL_FN} output_mode;
#if DIAG_PLATFORM_WINDOWS
    HANDLE outfile;
#else
    int outfile;
#endif
    void (*output_fn)(void *user_data, const char *);
} diag_output_t;

typedef struct {
    unsigned int backtrace_fields;
    unsigned int backtrace_count;
    unsigned int symbols_initialized : 1;
} diag_backtrace_param_t;

#if DIAG_PLATFORM_WINDOWS

typedef struct diag_context_t {
    CONTEXT *context;
    EXCEPTION_RECORD *exception_record;
} diag_context_t;

#else

typedef struct diag_context_t {
    int signal;
    siginfo_t *info;
#if DIAG_PLATFORM_SOLARIS
    ucontext_t *context;
#endif
} diag_context_t;

#endif

#define DIAG_ERR_INIT 1

/* Currently, this cannot fail and always returns 0. */
extern int diag_describe(diag_output_t *, diag_context_t *);

/* diag_backtrace() return codes:
 * 0:             no error
 * DIAG_ERR_INIT: some type of initialization error occurred
 */
extern int diag_backtrace(diag_output_t *, diag_backtrace_param_t *, diag_context_t *);

/* Currently, this cannot fail and always returns 0. */
extern int diag_backtrace_init(int symbols_initialized);

#ifdef __cplusplus
}
#endif

#endif /* DIAG_H */
