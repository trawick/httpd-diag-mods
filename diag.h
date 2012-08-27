/* Copyright 2012 Jeff Trawick, http://emptyhammock.com/
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

#ifdef WIN32
#include <windows.h>
#include <dbghelp.h>
#endif

#ifdef SOLARIS
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
#ifdef WIN32
    HANDLE outfile;
#else
    int outfile;
#endif
    void (*output_fn)(void *user_data, const char *);
    enum {DIAG_MODE_NORMAL, DIAG_MODE_EXCEPTION} calling_context;
#ifdef WIN32
    CONTEXT *context;
    EXCEPTION_RECORD *exception_record;
#else
    int signal;
#endif
    unsigned int backtrace_fields;
    unsigned int backtrace_count;
} diag_param_t;

typedef struct diag_context_t {
#ifdef WIN32
    CONTEXT *context;
#elif defined(SOLARIS)
    ucontext_t *context;
#else
    int foo;
#endif
} diag_context_t;

extern int diag_describe(diag_param_t *);
extern int diag_backtrace(diag_param_t *, diag_context_t *);

#ifdef __cplusplus
}
#endif

#endif /* DIAG_H */
