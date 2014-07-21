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

#include <stdio.h>
#include <string.h>

#include "diag.h"

#if DIAG_PLATFORM_UNIX
#include <unistd.h>
#endif

static void line_fmt(void *user_data, const char *s)
{
    char *linebuf = user_data;
    
    strcat(linebuf, s);
    strcat(linebuf, "<");
}

static void fmt(void *user_data, const char *s)
{
    printf("%s\n", s);
}

int y(void)
{
    diag_backtrace_param_t p = {0};
    diag_output_t o = {0};
    int rc;

#if DIAG_PLATFORM_WINDOWS
    o.outfile = GetStdHandle(STD_OUTPUT_HANDLE);
#else
    o.outfile = STDOUT_FILENO;
#endif

#define TESTCASE(btfields)                                           \
    printf("---------------------------------------------------\n"); \
    printf("testdiag: " #btfields "\n");                             \
    p.backtrace_fields = (btfields);                                 \
    rc += diag_backtrace(&o, &p, NULL);                              \
    printf("\n")

    rc = 0;
    o.output_mode = DIAG_WRITE_FD;
    TESTCASE(DIAG_BTFIELDS_ALL);

    o.output_mode = DIAG_CALL_FN;
    o.output_fn = fmt;

    TESTCASE(DIAG_BTFIELDS_ADDRESS);

    TESTCASE(DIAG_BTFIELDS_FUNCTION | DIAG_BTFIELDS_FN_OFFSET);

    TESTCASE(DIAG_BTFIELDS_FUNCTION);

    TESTCASE(DIAG_BTFIELDS_FUNCTION | DIAG_BTFIELDS_MODULE_NAME);

    TESTCASE(DIAG_BTFIELDS_FUNCTION | DIAG_BTFIELDS_MODULE_PATH);

    printf("---------------------------------------------------\n");
    printf("testdiag: ONELINER\n");

    {
        char linebuf[1024];

        linebuf[0] = '\0';
        o.user_data = linebuf;
        o.output_mode = DIAG_CALL_FN;
        o.output_fn = line_fmt;
        p.backtrace_fields = DIAG_BTFIELDS_FUNCTION;
        p.backtrace_count = 3;
        rc += diag_backtrace(&o, &p, NULL);
        if (linebuf[strlen(linebuf) - 1] == '<') {
            linebuf[strlen(linebuf) - 1] = '\0';
        }
        printf("%s\n", linebuf);
    }

    if (rc) {
        fprintf(stderr, "Some call to diag_backtrace() failed.\n");
    }

    return 0;
}

int x(void)
{
    return y();
}

int w(void)
{
    return x();
}

int main(void)
{
    return w();
}
