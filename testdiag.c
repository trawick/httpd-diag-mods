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

#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <unistd.h>
#endif

#include "diag.h"

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
    diag_param_t p = {0};

    p.calling_context = DIAG_MODE_NORMAL;

#ifdef __linux__
    p.outfile = STDOUT_FILENO;
    p.output_mode = DIAG_WRITE_FD;
    diag_backtrace(&p);
#endif

    printf("\n");

    p.output_mode = DIAG_CALL_FN;
    p.backtrace_fields = DIAG_BTFIELDS_ADDRESS;
    p.output_fn = fmt;
    diag_backtrace(&p);

    printf("\n");

    p.output_mode = DIAG_CALL_FN;
    p.backtrace_fields = DIAG_BTFIELDS_FUNCTION | DIAG_BTFIELDS_FN_OFFSET;
    p.output_fn = fmt;
    diag_backtrace(&p);

    printf("\n");

    p.output_mode = DIAG_CALL_FN;
    p.backtrace_fields = DIAG_BTFIELDS_FUNCTION;
    p.output_fn = fmt;
    diag_backtrace(&p);

    printf("\n");

    {
        char linebuf[1024];

        linebuf[0] = '\0';
        p.user_data = linebuf;
        p.output_mode = DIAG_CALL_FN;
        p.backtrace_fields = DIAG_BTFIELDS_FUNCTION;
        p.backtrace_count = 3;
        p.output_fn = line_fmt;
        diag_backtrace(&p);
        if (linebuf[strlen(linebuf) - 1] == '<') {
            linebuf[strlen(linebuf) - 1] = '\0';
        }
        printf("%s\n", linebuf);
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
