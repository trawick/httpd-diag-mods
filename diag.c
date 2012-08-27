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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag.h"

#ifndef DIAG_BT_LIMIT
#define DIAG_BT_LIMIT 25
#endif

#ifdef __linux__
#include <unistd.h>
#include <execinfo.h>
#endif

int diag_describe(diag_param_t *p)
{
    char buffer[256];
    size_t len;

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
    else {
        endmodule = firstbracket - 1;
    }

    if (fields & DIAG_BTFIELDS_MODULE_PATH) {
        /* implies DIAG_BTFIELDS_MODULE_NAME */
        outch = safe_copy(outch, lastoutch, s, endmodule);
    }
    else {
        s = lastslash + 1;
        if (fields & DIAG_BTFIELDS_MODULE_NAME) {
            outch = safe_copy(outch, lastoutch, s, endmodule);
        }
        s = endmodule + 1;
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
        const char *lastbracket = strchr(firstbracket, ']');
        
        if (lastbracket) {
            outch = safe_copy(outch, lastoutch,
                              firstbracket + 1,
                              lastbracket - 1);
        }
    }
}

#ifdef __linux__
int diag_backtrace(diag_param_t *p)
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

#else

#error not implemented on your platform

#endif
