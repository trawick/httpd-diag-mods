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

#if _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "diagplat.h"

#if DIAG_PLATFORM_LINUX || DIAG_PLATFORM_FREEBSD || DIAG_PLATFORM_MACOSX

#if DIAG_PLATFORM_LINUX
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <dlfcn.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "diag.h"

#ifndef DIAG_BT_LIMIT
#define DIAG_BT_LIMIT 25
#endif

#if DIAG_PLATFORM_UNIX
#include <unistd.h>
#endif

#if DIAG_HAVE_LIBUNWIND_BACKTRACE

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#elif DIAG_HAVE_EXECINFO_BACKTRACE

#include <execinfo.h>

#elif DIAG_PLATFORM_SOLARIS

#include <ucontext.h>
#include <dlfcn.h>

#elif DIAG_PLATFORM_WINDOWS

#include <windows.h>
#include <process.h>

#endif

static char *add_string(char *outch, const char *lastoutch,
                        const char *in_first, const char *in_last_param)
{
    const char *in_last = in_last_param;
    const char *inch;
    
    if (!outch) {
        return NULL;
    }
    
    if (outch >= (lastoutch - 1)) {
        return NULL;
    }

    if (!in_last) {
        in_last = in_first + strlen(in_first) - 1;
    }
    
    if (in_first > in_last) {
        return NULL;
    }
    
    inch = in_first;
    while (inch <= in_last) {
        *outch = *inch;
        ++outch;
        if (outch == lastoutch) {
            break;
        }
        ++inch;
    }
    *outch = '\0';

    return outch;
}

static char *add_int(char *outch, const char *lastoutch,
                     long long val, int radix)
{
    char buf[28];
    char *ch, *lastch;
    static const char *digits = "0123456789ABCDEF";
    int neg = 0;

    if (val < 0) {
        neg = 1;
        val = -val;
    }

    assert(radix == 10 || radix == 16);

    ch = lastch = buf + sizeof buf - 1;
    while (ch >= buf && val > 0) {
        int rem = val % radix;
        val = val / radix;
        *ch = digits[rem];
        --ch;
    }

    if (neg) {
        outch = add_string(outch, lastoutch, "-", NULL);
    }

    if (radix == 16) {
        outch = add_string(outch, lastoutch, "0x", NULL);
    }

    return add_string(outch, lastoutch, ch + 1, lastch);
}

static char *add_pointer(char *outch, const char *lastoutch,
                         void *vpointer)
{
#ifdef DIAG_BITS_64
    unsigned long long val = (unsigned long long)vpointer;
#else
    unsigned long val = (unsigned long)vpointer;
#endif
    int radix = 16;

    char buf[28];
    char *ch, *lastch;
    static const char *digits = "0123456789ABCDEF";

    assert(radix == 10 || radix == 16);

    ch = lastch = buf + sizeof buf - 1;
    while (ch >= buf && val > 0) {
        int rem = val % radix;
        val = val / radix;
        *ch = digits[rem];
        --ch;
    }

    if (radix == 16) {
        outch = add_string(outch, lastoutch, "0x", NULL);
    }

    return add_string(outch, lastoutch, ch + 1, lastch);
}

#if DIAG_PLATFORM_WINDOWS

struct exception_code_entry {
    DWORD symbol;
    const char *str;
};

#define one_ec_entry(s) {s,#s}
struct exception_code_entry ec_strs[] = {
    one_ec_entry(EXCEPTION_ACCESS_VIOLATION),
    one_ec_entry(EXCEPTION_ARRAY_BOUNDS_EXCEEDED),
    one_ec_entry(EXCEPTION_DATATYPE_MISALIGNMENT),
    one_ec_entry(EXCEPTION_ILLEGAL_INSTRUCTION),
    one_ec_entry(EXCEPTION_IN_PAGE_ERROR),
    one_ec_entry(EXCEPTION_INT_DIVIDE_BY_ZERO),
    one_ec_entry(EXCEPTION_STACK_OVERFLOW),
};

int diag_describe(diag_output_t *o, diag_context_t *c)
{
    char buf[256];
    char *outch;
    char *lastoutch = buf + sizeof buf - 1;
    const char *ch;
    int i;
    DWORD bytes_written;
    
    outch = buf;
    outch = add_string(outch, lastoutch, "Process id:        ", NULL);
    outch = add_int(outch, lastoutch, (long long)_getpid(), 10);

    if (o->output_mode == DIAG_WRITE_FD) {
        outch = add_string(outch, lastoutch, "\r\n", NULL);
        WriteFile(o->outfile, buf, strlen(buf), &bytes_written, NULL);
    }
    else {
        o->output_fn(o->user_data, buf);
    }

    if (c->exception_record) {
        outch = buf;
        outch = add_string(outch, lastoutch, "Exception code:    ", NULL);

        ch = NULL;
        for (i = 0; i < sizeof(ec_strs) / sizeof(ec_strs[0]); i++) {
            if (ec_strs[i].symbol == c->exception_record->ExceptionCode) {
                ch = ec_strs[i].str;
                break;
            }
        }
        if (ch == NULL) {
            outch = add_int(outch, lastoutch, (long long)c->exception_record->ExceptionCode, 10);
        }
        else {
            outch = add_string(outch, lastoutch, ch, NULL);
        }

        if (o->output_mode == DIAG_WRITE_FD) {
            outch = add_string(outch, lastoutch, "\r\n", NULL);
            WriteFile(o->outfile, buf, strlen(buf), &bytes_written, NULL);
        }
        else {
            o->output_fn(o->user_data, buf);
        }

        outch = buf;

        outch = add_string(outch, lastoutch, "Exception address: ", NULL);
        outch = add_int(outch, lastoutch, (long long)c->exception_record->ExceptionAddress, 16);

        if (o->output_mode == DIAG_WRITE_FD) {
            outch = add_string(outch, lastoutch, "\r\n", NULL);
            WriteFile(o->outfile, buf, strlen(buf), &bytes_written, NULL);
        }
        else {
            o->output_fn(o->user_data, buf);
        }
    }
    return 0;
}

#else

int diag_describe(diag_output_t *o, diag_context_t *c)
{
    char buf[256];
    char *outch;
    char *lastoutch = buf + sizeof buf - 1;

    outch = buf;
    outch = add_string(outch, lastoutch, "Process id:  ", NULL);
    outch = add_int(outch, lastoutch, (long long)getpid(), 10);
    if (o->output_mode == DIAG_WRITE_FD) {
        outch = add_string(outch, lastoutch, "\n", NULL);
        write(o->outfile, buf, strlen(buf));
    }
    else {
        o->output_fn(o->user_data, buf);
    }

    outch = buf;
    outch = add_string(outch, lastoutch, "Fatal signal: ", NULL);
    outch = add_int(outch, lastoutch, (long long)c->signal, 10);
    
    if (o->output_mode == DIAG_WRITE_FD) {
        outch = add_string(outch, lastoutch, "\n", NULL);
        write(o->outfile, buf, strlen(buf));
    }
    else {
        o->output_fn(o->user_data, buf);
    }

    if (c->info && c->info->si_addr) {
        outch = buf;

        if (c->signal == SIGSEGV) {
            outch = add_string(outch, lastoutch, "Invalid memory address: ", NULL);
        }
        else {
            outch = add_string(outch, lastoutch, "Faulting instruction: ", NULL);
        }
        outch = add_pointer(outch, lastoutch, c->info->si_addr);
        if (o->output_mode == DIAG_WRITE_FD) {
            outch = add_string(outch, lastoutch, "\n", NULL);
            write(o->outfile, buf, strlen(buf));
        }
        else {
            o->output_fn(o->user_data, buf);
        }
    }

    return 0;
}

#endif /* WIN32 */

static const char *end_of_field(const char *s)
{
    ++s;
    while (*s && !isspace(*s) && *s != '+' && *s != '>' && *s != ')'
           && *s != ']' && *s != '(' && *s != '[') {
        ++s;
    }
    return s - 1;
}

static void output_frame(char *outch, char *lastoutch, int fields,
                         const char *module_path,
                         const char *module, const char *function,
                         const char *offset, const char *address)
{
    int fn_missing = 0;

    if ((fields & DIAG_BTFIELDS_MODULE_PATH) && module_path) {
        outch = add_string(outch, lastoutch, module_path, end_of_field(module_path));
        outch = add_string(outch, lastoutch, ":", NULL);
    }
    else if ((fields & (DIAG_BTFIELDS_MODULE_NAME|DIAG_BTFIELDS_MODULE_PATH))
             && module) {
        outch = add_string(outch, lastoutch, module, end_of_field(module));
        outch = add_string(outch, lastoutch, ":", NULL);
    }

    if ((fields & DIAG_BTFIELDS_FUNCTION) && function) {
        outch = add_string(outch, lastoutch, function, end_of_field(function));
    }
    else {
        fn_missing = 1;
    }

    /* makes no sense to print offset if function is missing */
    if (!fn_missing && (fields & DIAG_BTFIELDS_FN_OFFSET) && offset) {
        outch = add_string(outch, lastoutch, "+", NULL);
        outch = add_string(outch, lastoutch, offset, end_of_field(offset));
    }

    if ((fn_missing || (fields & DIAG_BTFIELDS_ADDRESS)) && address) {
        if (!fn_missing) {
            outch = add_string(outch, lastoutch, " ", NULL);
        }
        outch = add_string(outch, lastoutch, address, end_of_field(address));
    }
}

#if !DIAG_HAVE_LIBUNWIND_BACKTRACE

#if DIAG_PLATFORM_LINUX
/* ./testdiag(diag_backtrace+0x75)[0x401824] */
static void format_frameinfo(const char *s,
                             unsigned int fields,
                             char *buf,
                             size_t buf_size)
{
    size_t s_len = strlen(s);
    char *outch = buf;
    char *lastoutch = buf + buf_size - 1;
    const char *lastslash, *firstparen, *firstbracket;
    const char *module_path, *module, *function, *offset, *address;
    
    lastslash = strrchr(s, '/');
    firstparen = strchr(s, '(');
    firstbracket = strchr(s, '[');
    
    if (!lastslash || !firstbracket) {
        /* format of string not recognized; just copy and get out */
        if (s_len < buf_size) {
            strcpy(buf, s);
        }
        else {
            memcpy(buf, s, buf_size - 1);
            buf[buf_size - 1] = 0;
        }
        return;
    }

    module_path = s;

    module = lastslash;
    if (module) {
        module += 1;
    }
    
    function = firstparen;
    if (function) {
        function += 1;
        if (*function == ')' || *function == '+') {
            /* here's one such scenario:
             * "/home/trawick/inst/24-64/modules/mod_backtrace.so(+0x2b6c) [0x7f2727df4b6c]"
             */
            function = NULL;
        }
    }

    offset = function;
    if (offset) {
        offset = strchr(function, '+');
        if (offset) {
            offset += 1;
        }
    }
    
    address = firstbracket;
    if (address) {
        address += 1;
    }
    
    output_frame(outch, lastoutch, fields, module_path,
                 module, function, offset, address);
}
#endif /* Linux */

#if DIAG_PLATFORM_MACOSX

static void format_frameinfo(const char *s,
                             unsigned int fields,
                             char *buf,
                             size_t buf_size)
{
    char *outch = buf;
    char *lastoutch = buf + buf_size - 1;
    const char *module_path = NULL; /* not implemented */
    const char *module, *address, *function, *offset;

    /* skip over frame number to find module */
    module = s;
    while (!isspace(*module)) {
        ++module;
    }
    while (isspace(*module)) {
        ++module;
    }

    /* find address */
    address = strstr(module, "0x");

    /* find function */
    function = address;
    if (function) {
        while (!isspace(*function)) {
            ++function;
        }
        while (isspace(*function)) {
            ++function;
        }
    }

    /* find offset */
    offset = function;

    if (offset) {
        offset = strstr(function, " + ");
        if (offset) {
            offset += 3;
        }
    }

    output_frame(outch, lastoutch, fields, module_path,
                 module, function, offset, address);
}
#endif /* OS X */

#if DIAG_PLATFORM_FREEBSD

/* 0x400ba7 <_init+807> at /usr/home/trawick/myhg/apache/mod/diag/testdiag */
static void format_frameinfo(const char *s,
                             unsigned int fields,
                             char *buf,
                             size_t buf_size)
{
    char *outch = buf;
    char *lastoutch = buf + buf_size - 1;
    const char *module_path, *module, *address, *function, *offset;

    address = s;

    function = address;
    function = strchr(function, '<');
    if (function) {
        function += 1;
    }

    offset = function;
    if (offset) {
        offset = strchr(offset, '+');
        if (offset) {
            offset += 1;
        }
    }

    module_path = offset;
    if (module_path) {
        module_path = strstr(module_path, " at ");
        if (module_path) {
            module_path += 4;
        }
    }

    module = module_path;
    if (module) {
        module = strrchr(module, '/');
        if (module) {
            module += 1;
        }
    }

    output_frame(outch, lastoutch, fields, module_path,
                 module, function, offset, address);
}
#endif /* FreeBSD */

#endif /* !DIAG_HAVE_LIBUNWIND_BACKTRACE */

#if DIAG_HAVE_LIBUNWIND_BACKTRACE

int diag_backtrace(diag_output_t *o, diag_backtrace_param_t *p, diag_context_t *c)
{
    char frame[128];
    char addr_buf[20];
    char offset_buf[20];
    char name_buf[80];
    char *name;
    const char *module_path, *module;
    int count, cur, rc;
    unw_context_t ctx;
    unw_cursor_t csr;
    unw_word_t ip, offp;
#if DIAG_PLATFORM_LINUX || DIAG_PLATFORM_FREEBSD || DIAG_PLATFORM_MACOSX
    Dl_info info;
#endif

    if (p->backtrace_count && p->backtrace_count < DIAG_BT_LIMIT) {
        count = p->backtrace_count;
    }
    else {
        count = DIAG_BT_LIMIT;
    }
    
    rc = unw_getcontext(&ctx);
    if (!rc) {
        rc = unw_init_local(&csr, &ctx);
    }

    if (rc) {
        return DIAG_ERR_INIT;
    }

    cur = 0;
    while ((rc = unw_step(&csr)) > 0) {

        cur++;
        if (cur > count) {
            break;
        }

        unw_get_reg(&csr, UNW_REG_IP, &ip);

        if (!ip) {
            break;
        }

        add_int(addr_buf, addr_buf + sizeof addr_buf - 1, ip, 16);

        rc = unw_get_proc_name(&csr, name_buf, sizeof name_buf, &offp);
        if (rc && rc != UNW_ENOMEM) {
            name = NULL;
        }
        else {
            name = name_buf;
        }

        module = module_path = NULL;
#if DIAG_PLATFORM_LINUX || DIAG_PLATFORM_FREEBSD || DIAG_PLATFORM_MACOSX
        if (p->backtrace_fields
            & (DIAG_BTFIELDS_MODULE_PATH | DIAG_BTFIELDS_MODULE_NAME)) {
            if ((rc = dladdr((void *)ip, &info)) != 0) {
                module_path = info.dli_fname;
                module = strrchr(module_path, '/');
                if (module) {
                    module += 1;
                }
            }
        }
#endif

        add_int(offset_buf, offset_buf + sizeof offset_buf - 1,
                offp, 16);
        output_frame(frame, frame + sizeof frame - 1,
                     p->backtrace_fields,
                     module_path, module, name, offset_buf, addr_buf);

        if (o->output_mode == DIAG_CALL_FN) {
            o->output_fn(o->user_data, frame);
        }
        else {
            write(o->outfile, frame, strlen(frame));
            write(o->outfile, "\n", 1);
        }
    }

    return 0;
}

#elif DIAG_HAVE_EXECINFO_BACKTRACE

int diag_backtrace(diag_output_t *o, diag_backtrace_param_t *p, diag_context_t *c)
{
    void *pointers[DIAG_BT_LIMIT];
    int count;
    int size;
    char **strings;
    int i;

    if (p->backtrace_count && p->backtrace_count < DIAG_BT_LIMIT) {
        count = p->backtrace_count;
    }
    else {
        count = DIAG_BT_LIMIT;
    }

    size = backtrace(pointers, DIAG_BT_LIMIT);
    if (size > 0) {
        if (o->output_mode == DIAG_WRITE_FD) {
            /* XXX we won't be able to filter out diag_backtrace() */
            backtrace_symbols_fd(pointers, size, o->outfile);
        }
        else {
            strings = backtrace_symbols(pointers, size);
            for (i = 0; i < size && count; i++) {
                char buf[256] = {0};

                if (strstr(strings[i], "diag_backtrace")) {
                    continue;
                }
                
                format_frameinfo(strings[i], 
                                 p->backtrace_fields,
                                 buf,
                                 sizeof buf);
                o->output_fn(o->user_data, buf);
                count--;
            }
            free(strings);
        }
    }
    return 0;
}

#elif DIAG_PLATFORM_SOLARIS

/* seen on Solaris 10: the ucontext_t passed to signal handler
 * is the caller of the function that crashed, rather than that
 * function; we need to get the context ourselves and skip over
 * a few stackframes
 */

#define BROKEN_SIGNAL_UCONTEXT_T
#define FRAMES_TO_SKIP 3

typedef struct {
#ifdef BROKEN_SIGNAL_UCONTEXT_T
    int skips;
#endif
    int cur;
    int count;
    diag_output_t *o;
    diag_backtrace_param_t *p;
} fmt_userdata_t;

static int fmt(uintptr_t pc, int sig, void *userdata)
{
    fmt_userdata_t *u = userdata;
    diag_backtrace_param_t *p = u->p;
    diag_output_t *o = u->o;
    int rc;
    Dl_info dlip = {0};

#ifdef BROKEN_SIGNAL_UCONTEXT_T
    if (u->skips) {
        --u->skips;
        return 0;
    }
#endif

    rc = dladdr1((void *)pc, &dlip, NULL, 0);
    if (rc != 0) {
        char buf[128];
        char addr_buf[20];
        char offset_buf[20];
        const char *module_path = dlip.dli_fname;
        const char *module = NULL;
        const char *function = dlip.dli_sname;

        module = module_path;
        if (module) {
            module = strrchr(module_path, '/');
            if (module) {
                module += 1;
            }
        }
        add_int(addr_buf, addr_buf + sizeof addr_buf - 1, (long long)pc, 16);
        add_int(offset_buf, offset_buf + sizeof offset_buf - 1,
                (long long)((char *)pc - (char *)dlip.dli_saddr), 16);

        output_frame(buf, buf + sizeof buf - 1,
                     p->backtrace_fields,
                     module_path, module, function,
                     offset_buf, addr_buf);

        if (o->output_mode == DIAG_CALL_FN) {
            o->output_fn(o->user_data, buf);
        }
        else {
            write(o->outfile, buf, strlen(buf));
            write(o->outfile, "\n", 1);
        }
    }
    else {
        /* printf("dladdr1 failed, errno %d\n", errno); */
    }

    ++u->cur;
    return u->cur >= u->count;
}

int diag_backtrace(diag_output_t *o, diag_backtrace_param_t *p, diag_context_t *c)
{
    fmt_userdata_t u = {0};
    ucontext_t context;

    if (c && c->context) {
        context = *c->context;
    }
    else {
        getcontext(&context);
    }

    if (p->backtrace_count && p->backtrace_count < DIAG_BT_LIMIT) {
        u.count = p->backtrace_count;
    }
    else {
        u.count = DIAG_BT_LIMIT;
    }

    if (o->output_mode == DIAG_WRITE_FD) {
        printstack(o->outfile);
    }
    else {
#ifdef BROKEN_SIGNAL_UCONTEXT_T
        if (c && c->context) {
            /* must ignore user context, which probably came from
             * signal handler
             */
            u.skips = FRAMES_TO_SKIP;
            getcontext(&context);
        }
#endif
        u.p = p;
        u.o = o;
        walkcontext(&context, fmt, &u);
    }


    return 0;
}

#elif DIAG_PLATFORM_WINDOWS

int diag_backtrace(diag_output_t *o, diag_backtrace_param_t *p, diag_context_t *c)
{
    int cur = 0, count;
    STACKFRAME64 stackframe;
    CONTEXT context;
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();
    DWORD bytes_written;

    if (c) {
        context = *c->context;
    }
    else {
        RtlCaptureContext(&context);
    }

    if (p->backtrace_count && p->backtrace_count < DIAG_BT_LIMIT) {
        count = p->backtrace_count;
    }
    else {
        count = DIAG_BT_LIMIT;
    }

    memset(&stackframe, 0, sizeof stackframe);
    stackframe.AddrPC.Mode = 
        stackframe.AddrFrame.Mode =
            stackframe.AddrStack.Mode = AddrModeFlat;

#ifdef DIAG_BITS_64
    stackframe.AddrPC.Offset    = context.Rip;
    stackframe.AddrFrame.Offset = context.Rbp;
    stackframe.AddrStack.Offset = context.Rsp;
#else
    stackframe.AddrPC.Offset    = context.Eip;
    stackframe.AddrFrame.Offset = context.Ebp;
    stackframe.AddrStack.Offset = context.Esp;
#endif

    if (!p->symbols_initialized) {
        SymInitialize(process, NULL, TRUE);
    }

    while (StackWalk64(
#ifdef DIAG_BITS_64
                       IMAGE_FILE_MACHINE_AMD64,
#else
                       IMAGE_FILE_MACHINE_I386,
#endif
                       process, thread,
                       &stackframe,
                       &context,
                       NULL,                       /* ReadMemoryRoutine */
                       SymFunctionTableAccess64,   /* FunctionTableAccessRoutine */
                       SymGetModuleBase64,         /* GetModuleBaseRoutine */
                       NULL)                       /* TranslateAddress */
           == TRUE) {
        char symbol_buffer[128] = {0};
        IMAGEHLP_SYMBOL64 *symbol = (IMAGEHLP_SYMBOL64 *)&symbol_buffer;
        DWORD64 ignored;
        const char *function;
        const char *offset;
        char address_buf[20], offset_buf[20];
        char buf[128];
        char *outch = buf;
        char *lastoutch = buf + sizeof buf - 1;

        if (cur + 1 > count) { /* avoid loop on corrupted chain, respect caller's wishes */
            break;
        }
        symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
        symbol->MaxNameLength = sizeof(symbol_buffer) - sizeof(IMAGEHLP_SYMBOL64);
        ignored = 0;
        if (SymGetSymFromAddr64(process, stackframe.AddrPC.Offset, &ignored, symbol) != TRUE) {
            function = NULL;
            offset = NULL;
        }
        else {
            function = symbol->Name;
            add_int(offset_buf, offset_buf + sizeof offset_buf - 1,
                    stackframe.AddrPC.Offset - symbol->Address, 16);
            offset = offset_buf;
        }

        add_int(address_buf, address_buf + sizeof address_buf - 1,
                stackframe.AddrPC.Offset, 16);

        if (function && !strcmp(function, "diag_backtrace")) {
            /* filter outselves out */
            continue;
        }

        cur++; /* gonna keep this frame, so count it */

        output_frame(outch, lastoutch, p->backtrace_fields,
                     NULL, /* no module path */
                     NULL, /* no module */
                     function,
                     offset,
                     address_buf);

        if (o->output_mode == DIAG_CALL_FN) {
            o->output_fn(o->user_data, buf);
        }
        else {
            WriteFile(o->outfile, buf, strlen(buf), &bytes_written, NULL);
            WriteFile(o->outfile, "\r\n", 2, &bytes_written, NULL);
        }
    }

    return 0;
}

#else

#error not implemented on your platform

#endif

static void fmt_dummy(void *userdata, const char *buffer)
{
}

static void dummy_backtrace(int symbols_initialized)
{
    diag_backtrace_param_t p = {0};
    diag_output_t o = {0};

    p.symbols_initialized = symbols_initialized;
    o.output_mode = DIAG_CALL_FN;
    o.output_fn = fmt_dummy;
    p.backtrace_fields = DIAG_BTFIELDS_FUNCTION;
    p.backtrace_count = 10;
    diag_backtrace(&o, &p, NULL);
}

int diag_backtrace_init(int symbols_initialized)
{
    dummy_backtrace(symbols_initialized);
    return 0;
}
