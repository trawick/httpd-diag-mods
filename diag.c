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

#if _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag.h"

#ifndef DIAG_BT_LIMIT
#define DIAG_BT_LIMIT 25
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__) || defined(__MACH__)
#define HAVE_EXECINFO_BACKTRACE
#endif

#ifdef HAVE_EXECINFO_BACKTRACE
#include <unistd.h>
#include <execinfo.h>
#endif

#ifdef WIN32
#include <windows.h>

#if _MSC_VER
#define snprintf _snprintf
#endif
#endif

int diag_describe(diag_param_t *p)
{
#ifndef WIN32
    char buffer[256];
    size_t len;
#endif

    assert(p->calling_context == DIAG_MODE_EXCEPTION);

#ifdef WIN32
#else
    len = snprintf(buffer, sizeof buffer,
                   "Child process %ld exited with signal %d.\n",
                   (long)getpid(), p->signal);
    
    if (p->output_mode == DIAG_WRITE_FD) {
        write(p->outfile, buffer, len);
    }
    else {
        p->output_fn(p->user_data, buffer);
    }
#endif

    return 0;
}

static char *safe_copy(char *outch, const char *lastoutch,
                       const char *in_first, const char *in_last)
{
    const char *inch;
    
    if (!outch) {
        return NULL;
    }
    
    if (outch >= (lastoutch - 1)) {
        return NULL;
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

#ifndef WIN32
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
    static const char *colon = ":";

    if ((fields & DIAG_BTFIELDS_MODULE_PATH) && module_path) {
        outch = safe_copy(outch, lastoutch, module_path, end_of_field(module_path));
        outch = safe_copy(outch, lastoutch, colon, colon);
    }
    else if ((fields & (DIAG_BTFIELDS_MODULE_NAME|DIAG_BTFIELDS_MODULE_PATH))
             && module) {
        outch = safe_copy(outch, lastoutch, module, end_of_field(module));
        outch = safe_copy(outch, lastoutch, colon, colon);
    }

    if ((fields & DIAG_BTFIELDS_FUNCTION) && function) {
        outch = safe_copy(outch, lastoutch, function, end_of_field(function));
    }
    else {
        fn_missing = 1;
    }

    if ((fields & DIAG_BTFIELDS_FN_OFFSET) && offset) {
        static const char *plus = "+";

        outch = safe_copy(outch, lastoutch, plus, plus);
        outch = safe_copy(outch, lastoutch, offset, end_of_field(offset));
    }

    if ((fn_missing || (fields & DIAG_BTFIELDS_ADDRESS)) && address) {
        outch = safe_copy(outch, lastoutch, address, end_of_field(address));
    }
}
#endif /* not WIN32 */

#ifdef __linux__
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
        if (*function == ')') {
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
#endif /* __linux__ */

#ifdef __MACH__

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
#endif /* __MACH__ */

#if defined(__FreeBSD__) || defined(__DragonFly__) 

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
#endif /* __FreeBSD__ || __DragonFly__ */

#ifdef HAVE_EXECINFO_BACKTRACE
int diag_backtrace(diag_param_t *p, diag_context_t *c)
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
        if (p->output_mode == DIAG_WRITE_FD) {
            backtrace_symbols_fd(pointers, size, p->outfile);
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
                p->output_fn(p->user_data, buf);
                count--;
            }
            free(strings);
        }
    }
    return size;
}

#elif defined(WIN32)

int diag_backtrace(diag_param_t *p, diag_context_t *c)
{
    int cur = 0, count;
    STACKFRAME64 stackframe;
    CONTEXT context;
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();
    char symbol_buffer[512] = {0};
    IMAGEHLP_SYMBOL64 *symbol = (IMAGEHLP_SYMBOL64 *)&symbol_buffer;
    DWORD64 ignored;

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

    stackframe.AddrPC.Offset    = context.Eip;
    stackframe.AddrFrame.Offset = context.Ebp;
    stackframe.AddrStack.Offset = context.Esp;

    if (SymInitialize(process, 
                      "C:\\Apache22\\bin;C:\\Apache22\\modules;c:\\Symbols;c:\\windows\\symbols;"
                      "c:\\windows\\symbols\\dll",
                      /* "SRV*C:\\MyLocalSymbols*http://msdl.microsoft.com/download/symbols" */
                      TRUE) != TRUE) {
        /*
        fprintf(log, "SymInitialize() failed with error %d\n",
                GetLastError());
        */
    }

    while (StackWalk64(IMAGE_FILE_MACHINE_I386,
                       process, thread,
                       &stackframe,
                       &context,
                       NULL,                       /* ReadMemoryRoutine */
                       SymFunctionTableAccess64,   /* FunctionTableAccessRoutine */
                       SymGetModuleBase64,         /* GetModuleBaseRoutine */
                       NULL)                       /* TranslateAddress */
           == TRUE) {
        cur++;
        if (cur > count) { /* avoid loop on corrupted chain, respect caller's wishes */
            break;
        }
        symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
        symbol->MaxNameLength = sizeof(symbol_buffer) - sizeof(IMAGEHLP_SYMBOL64);
        ignored = 0;
        if (SymGetSymFromAddr64(process, stackframe.AddrPC.Offset, &ignored, symbol) != TRUE) {
            snprintf(symbol->Name, symbol->MaxNameLength, "no-symbol-%d", GetLastError());
        }
        {
            char buf[128] = "no-data";
            char *outch = buf;
            const char *lastoutch = buf + sizeof buf - 1;
            static const char *space = " ";

            if (p->backtrace_fields & DIAG_BTFIELDS_FUNCTION) {
                outch = safe_copy(outch, lastoutch,
                                  symbol->Name,
                                  symbol->Name + strlen(symbol->Name) - 1);
            }

            if (p->backtrace_fields & DIAG_BTFIELDS_ADDRESS) {
                char addrbuf[30];

                if (outch != buf) {
                    outch = safe_copy(outch, lastoutch,
                                      space,
                                      space);
                }

                snprintf(addrbuf, sizeof addrbuf, "0x%I64X",
                         stackframe.AddrPC.Offset);

                outch = safe_copy(outch, lastoutch,
                                  addrbuf,
                                  addrbuf + strlen(addrbuf) - 1);
            }

            if (p->output_mode == DIAG_CALL_FN) {
                p->output_fn(p->user_data, buf);
            }
            else {
                WriteFile(p->outfile, buf, strlen(buf), NULL, NULL);
                WriteFile(p->outfile, "\r\n", 2, NULL, NULL);
            }
        }
    }

    return 0;
}

#else

#error not implemented on your platform

#endif
