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

#include <stdio.h>
#include <string.h>

#include "diag.h"

#if DIAG_PLATFORM_UNIX
#include <signal.h>
#include <unistd.h>
#endif

#if DIAG_PLATFORM_WINDOWS

static LONG WINAPI unhandled_exception_filter(EXCEPTION_POINTERS *ep)
{
    diag_context_t c = {0};
    diag_output_t o = {0};
    diag_backtrace_param_t p = {0};

    c.context = ep->ContextRecord;
    c.exception_record = ep->ExceptionRecord;

    o.output_mode = DIAG_WRITE_FD;
    o.outfile = GetStdHandle(STD_OUTPUT_HANDLE);

    diag_describe(&o, &c);

    p.backtrace_fields =
        DIAG_BTFIELDS_MODULE_NAME | DIAG_BTFIELDS_FUNCTION | DIAG_BTFIELDS_FN_OFFSET;

    diag_backtrace(&o, &p, &c);

    /* Don't execute other handlers, as we want this test program to fail
     * immediately.
     */
    /* return EXCEPTION_CONTINUE_SEARCH; */
    return EXCEPTION_EXECUTE_HANDLER;
}

#else

static void fmt(void *user_data, const char *s)
{
    write(STDOUT_FILENO, s, strlen(s));
    write(STDOUT_FILENO, "\n", 1);
}

static void signal_handler(int sig, siginfo_t *info, void *v)
{
    diag_context_t c = {0};
    diag_output_t o = {0};
    diag_backtrace_param_t p = {0};
#if DIAG_PLATFORM_SOLARIS
    ucontext_t *uc = v;
#endif

    c.signal = sig;
    c.info = info;
#if DIAG_PLATFORM_SOLARIS
    c.context = uc;
#endif

    o.output_mode = DIAG_WRITE_FD;
    o.outfile = STDOUT_FILENO;

    diag_describe(&o, &c);

    write(STDOUT_FILENO, "Backtrace to file descriptor:\n",
          strlen("Backtrace to file descriptor:\n"));
    p.backtrace_fields =
        DIAG_BTFIELDS_MODULE_NAME | DIAG_BTFIELDS_FUNCTION | DIAG_BTFIELDS_FN_OFFSET;

    diag_backtrace(&o, &p, &c);

    write(STDOUT_FILENO, "Backtrace to callback:\n",
          strlen("Backtrace to callback:\n"));

    o.output_mode = DIAG_CALL_FN;
    o.output_fn = fmt;
    diag_backtrace(&o, &p, &c);
}

#endif

int y(void)
{
    *(int *)0xDEADBEEF = 0xC0FFEE;
    /* unreached */
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
#if DIAG_PLATFORM_WINDOWS
    SetUnhandledExceptionFilter(unhandled_exception_filter);
#else
    struct sigaction sa, oldsa;

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigaction(SIGSEGV, &sa, &oldsa);
#endif

    diag_backtrace_init(0);

    return w();
}
