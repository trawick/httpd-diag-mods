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

#ifdef __linux__
static void format_frameinfo(const char *s,
                             unsigned int fields,
                             char *buf,
                             size_t buf_size)
{
    size_t s_len = strlen(s);
    char *outch = buf;
    const char *lastoutch = buf + buf_size - 1;
    const char *lastslash, *firstparen, *firstbracket, *endmodule;
    int fn_missing = 0;
    
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
    }
    if (firstparen) {
        endmodule = firstparen - 1;
    }
    else if (firstbracket) {
        endmodule = firstbracket - 1;
    }
    else {
        endmodule = NULL;
    }

    if (fields & DIAG_BTFIELDS_MODULE_PATH) {
        /* implies DIAG_BTFIELDS_MODULE_NAME */
        if (s && endmodule) {
            outch = safe_copy(outch, lastoutch, s, endmodule);
        }
    }
    else {
        if (s && endmodule) {
            s = lastslash + 1;
            if (fields & DIAG_BTFIELDS_MODULE_NAME) {
                outch = safe_copy(outch, lastoutch, s, endmodule);
            }
            s = endmodule + 1;
        }
    }

    if (fields & DIAG_BTFIELDS_FUNCTION) {
        if (firstparen) {
            const char *lastparen = strchr(firstparen, ')');
            const char *plus = strchr(firstparen, '+');
            const char *copyto;

            if (fields & DIAG_BTFIELDS_FN_OFFSET) {
                copyto = lastparen;
            }
            else if (plus) {
                copyto = plus;
            }
            else {
                copyto = NULL;
            }
        
            if (copyto && lastparen && firstparen + 1 != copyto) {
                outch = safe_copy(outch, lastoutch,
                                  firstparen + 1, copyto - 1);
                s = lastparen + 1;
            }
            else {
                fn_missing = 1;
            }
        }
        else {
            fn_missing = 1;
        }
    }

    if ((fields & DIAG_BTFIELDS_ADDRESS) || fn_missing) {
        if (firstbracket) {
            const char *lastbracket = strchr(firstbracket, ']');
            if (lastbracket) {
                outch = safe_copy(outch, lastoutch,
                                  firstbracket + 1,
                                  lastbracket - 1);
            }
        }
    }
}
#endif

#ifdef __MACH__

static const char *end_of_field(const char *s)
{
    ++s;
    while (*s && !isspace(*s)) {
        ++s;
    }
    return s - 1;
}

static void format_frameinfo(const char *s,
                             unsigned int fields,
                             char *buf,
                             size_t buf_size)
{
    char *outch = buf;
    const char *lastoutch = buf + buf_size - 1;
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

    if ((fields & DIAG_BTFIELDS_MODULE_NAME) && module) {
        outch = safe_copy(outch, lastoutch, module, end_of_field(module));
    }

    if ((fields & DIAG_BTFIELDS_FUNCTION) && function) {
        outch = safe_copy(outch, lastoutch, function, end_of_field(function));
    }

    if ((fields & DIAG_BTFIELDS_FN_OFFSET) && offset) {
        static const char *plus = "+";

        outch = safe_copy(outch, lastoutch, plus, plus);
        outch = safe_copy(outch, lastoutch, offset, end_of_field(offset));
    }

    if ((fields & DIAG_BTFIELDS_ADDRESS) && address) {
        outch = safe_copy(outch, lastoutch, address, end_of_field(address));
    }
}
#endif

#if defined(__FreeBSD__) || defined(__DragonFly__) 

static const char *end_of_field(const char *s)
{
    ++s;
    while (*s && !isspace(*s) && *s != '+' && *s != '>') {
        ++s;
    }
    return s - 1;
}

/* 0x400ba7 <_init+807> at /usr/home/trawick/myhg/apache/mod/diag/testdiag */
static void format_frameinfo(const char *s,
                             unsigned int fields,
                             char *buf,
                             size_t buf_size)
{
    char *outch = buf;
    const char *lastoutch = buf + buf_size - 1;
    const char *module, *address, *function, *offset;

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

    module = offset;
    if (module) {
        module = strstr(module, " at ");
        if (module) {
            module += 4;
        }
    }

    if ((fields & DIAG_BTFIELDS_MODULE_NAME) && module) {
        outch = safe_copy(outch, lastoutch, module, end_of_field(module));
    }

    if ((fields & DIAG_BTFIELDS_FUNCTION) && function) {
        outch = safe_copy(outch, lastoutch, function, end_of_field(function));
    }

    if ((fields & DIAG_BTFIELDS_FN_OFFSET) && offset) {
        static const char *plus = "+";

        outch = safe_copy(outch, lastoutch, plus, plus);
        outch = safe_copy(outch, lastoutch, offset, end_of_field(offset));
    }

    if ((fields & DIAG_BTFIELDS_ADDRESS) && address) {
        outch = safe_copy(outch, lastoutch, address, end_of_field(address));
    }
}
#endif

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
    int cur = 0, limit = 25;
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
        if (cur > limit) { /* avoid loop on corrupted chain */
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
