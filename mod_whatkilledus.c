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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "ap_mpm.h"

#include "mod_backtrace.h"

#if DIAG_PLATFORM_UNIX
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
APLOG_USE_MODULE(whatkilledus);
#endif

#if DIAG_PLATFORM_UNIX
#define DEFAULT_REL_LOGFILENAME "logs/whatkilledus_log"
#else
#define DEFAULT_REL_LOGFILENAME "logs/whatkilledus.log"
#endif

/* Use this LOG_PREFIX only on non-debug messages.  This provides a module
 * identifer with httpd < 2.4.
 */
#if AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
#define LOG_PREFIX ""
#else
#define LOG_PREFIX "mod_whatkilledus: "
#endif

static APR_OPTIONAL_FN_TYPE(backtrace_describe_exception) *describe_exception;
static APR_OPTIONAL_FN_TYPE(backtrace_get_backtrace) *get_backtrace;

#if DIAG_PLATFORM_UNIX
static int exception_hook_enabled;
#endif

static volatile /* imperfect but probably good enough */ int already_crashed = 0;

static server_rec *main_server;
static const char *logfilename;

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

static void build_header(char *buf, size_t buflen,
                         int year, int month, int day, int hour, int minute, int second)
{
    char *outch = buf, *lastoutch = buf + buflen - 1;

    outch = add_string(outch, lastoutch, "**** Crash at ", NULL);
    outch = add_int(outch, lastoutch, (long long)year, 10);
    outch = add_string(outch, lastoutch, "-", NULL);
    if (month < 10) {
        outch = add_string(outch, lastoutch, "0", NULL);
    }
    outch = add_int(outch, lastoutch, (long long)month, 10);
    outch = add_string(outch, lastoutch, "-", NULL);
    if (day < 10) {
        outch = add_string(outch, lastoutch, "0", NULL);
    }
    outch = add_int(outch, lastoutch, (long long)day, 10);
    outch = add_string(outch, lastoutch, " ", NULL);
    if (hour < 10) {
        outch = add_string(outch, lastoutch, "0", NULL);
    }
    outch = add_int(outch, lastoutch, (long long)hour, 10);
    outch = add_string(outch, lastoutch, ":", NULL);
    if (minute < 10) {
        outch = add_string(outch, lastoutch, "0", NULL);
    }
    outch = add_int(outch, lastoutch, (long long)minute, 10);
    outch = add_string(outch, lastoutch, ":", NULL);
    if (second < 10) {
        outch = add_string(outch, lastoutch, "0", NULL);
    }
    outch = add_int(outch, lastoutch, (long long)second, 10);
}

#if DIAG_PLATFORM_WINDOWS

static LONG WINAPI whatkilledus_crash_handler(EXCEPTION_POINTERS *ep)
{
    bt_param_t p = {0};
    diag_context_t c = {0};
    HANDLE logfile;
    SYSTEMTIME now;
    char buf[128];

    if (already_crashed) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    ++already_crashed;

    logfile = CreateFile(logfilename, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (logfile == INVALID_HANDLE_VALUE) {
        /* nothing to do */
        return EXCEPTION_CONTINUE_SEARCH;
    }

    SetFilePointer(logfile, 0, NULL, FILE_END);

    GetLocalTime(&now);

    build_header(buf, sizeof buf, now.wYear, now.wMonth, now.wDay,
                 now.wHour, now.wMinute, now.wSecond);

    WriteFile(logfile, buf, strlen(buf), NULL, NULL);
    WriteFile(logfile, "\r\n", 2, NULL, NULL);

    p.output_mode = BT_OUTPUT_FILE;
    p.output_style = BT_OUTPUT_MEDIUM;
    p.outfile = logfile;

    c.context = ep->ContextRecord;
    c.exception_record = ep->ExceptionRecord;

    if (describe_exception) {
        describe_exception(&p, &c);
        WriteFile(logfile, "\r\n", 2, NULL, NULL);
    }

    if (get_backtrace) {
        get_backtrace(&p, &c);
        WriteFile(logfile, "\r\n", 2, NULL, NULL);
    }

    CloseHandle(logfile);

    return EXCEPTION_CONTINUE_SEARCH;
}

#else

static int whatkilledus_fatal_exception(ap_exception_info_t *ei)
{
    bt_param_t p = {0};
    diag_context_t c = {0};
    int logfile;
    time_t now;
    struct tm tm;
    char buf[128];

    if (already_crashed) {
        return OK;
    }
    ++already_crashed;

    logfile = open(logfilename, O_WRONLY | O_APPEND | O_CREAT,
                   S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (logfile == -1) {
        /* nothing to do */
        return OK;
    }

    time(&now);
    /* whoops, not necessarily async-signal safe */
    localtime_r(&now, &tm);

    build_header(buf, sizeof buf, 1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec);
    write(logfile, buf, strlen(buf));
    write(logfile, "\n", 1);

    p.output_mode = BT_OUTPUT_FILE;
    p.output_style = BT_OUTPUT_MEDIUM;
    p.outfile = logfile;

    c.signal = ei->sig;

    if (describe_exception) {
        describe_exception(&p, &c);
        write(logfile, "\n", 1);
    }

    if (get_backtrace) {
        get_backtrace(&p, NULL);
        write(logfile, "\n", 1);
    }

    close(logfile);

    return OK;
}

#endif

static void whatkilledus_optional_fn_retrieve(void)
{
    describe_exception = APR_RETRIEVE_OPTIONAL_FN(backtrace_describe_exception);
    get_backtrace = APR_RETRIEVE_OPTIONAL_FN(backtrace_get_backtrace);
}

static void whatkilledus_child_init(apr_pool_t *p, server_rec *s)
{
    main_server = s;

#if DIAG_PLATFORM_WINDOWS
    /* must back this out before this DLL is unloaded;
     * but previous exception filter might have been unloaded too
     */
    SetUnhandledExceptionFilter(whatkilledus_crash_handler);
#endif
}

static void crash(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                  LOG_PREFIX "about to crash");

    *(int *)0xdeadbeef = 0xcafebabe;
}

static int whatkilledus_handler(request_rec *r)
{
    if (!strcmp(r->handler, "whatkilledus-crash-handler")) {
        crash(r);
        /* unreached */
    }

    return DECLINED;
}

static int whatkilledus_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
#if DIAG_PLATFORM_UNIX
    if (!exception_hook_enabled) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     LOG_PREFIX "EnableExceptionHook must be set to On");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif

    logfilename = ap_server_root_relative(pconf, DEFAULT_REL_LOGFILENAME);

    return OK;
}

static void whatkilledus_register_hooks(apr_pool_t *p)
{
#if DIAG_PLATFORM_UNIX
    ap_hook_fatal_exception(whatkilledus_fatal_exception, NULL, NULL,
                            APR_HOOK_MIDDLE);
#endif
    ap_hook_handler(whatkilledus_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_optional_fn_retrieve(whatkilledus_optional_fn_retrieve, NULL, NULL,
                                 APR_HOOK_MIDDLE);
    ap_hook_post_config(whatkilledus_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(whatkilledus_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

#if DIAG_PLATFORM_UNIX
static const char *check_exception_hook(cmd_parms *cmd, void *dummy, const char *arg)
{
    if (strcasecmp(arg, "on") == 0) {
        exception_hook_enabled = 1;
    }
    else if (strcasecmp(arg, "off") == 0) {
        exception_hook_enabled = 0;
    }
    return DECLINE_CMD;
}
#endif

static const command_rec whatkilledus_cmds[] =
{
#if DIAG_PLATFORM_UNIX
    AP_INIT_TAKE1("EnableExceptionHook", check_exception_hook, NULL, RSRC_CONF,
                  "Check if EnableExceptionHook is On"),
#endif
    {NULL}
};

module AP_MODULE_DECLARE_DATA whatkilledus_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    whatkilledus_cmds,
    whatkilledus_register_hooks
};
