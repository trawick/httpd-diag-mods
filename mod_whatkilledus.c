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
#include <time.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_mpm.h"

#include "mod_backtrace.h"

#include "diag_mod_version.h"

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
#define END_OF_LINE "\n"
#else
#define DEFAULT_REL_LOGFILENAME "logs/whatkilledus.log"
#define END_OF_LINE "\r\n"
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

#if DIAG_PLATFORM_WINDOWS
static LPTOP_LEVEL_EXCEPTION_FILTER old_exception_filter;
#endif

static volatile /* imperfect but probably good enough */ int already_crashed = 0;

static server_rec *main_server;
static const char *logfilename;

#if DIAG_PLATFORM_WINDOWS
static __declspec(thread) const char *thread_logdata;
#else
static const char *global_logdata;
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
    DWORD bytes_written;
    const char *logdata;

    if (already_crashed) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    ++already_crashed;

    if (old_exception_filter) {
        SetUnhandledExceptionFilter(old_exception_filter);
        old_exception_filter = NULL;
    }

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

    WriteFile(logfile, buf, strlen(buf), &bytes_written, NULL);
    WriteFile(logfile, "\r\n", 2, &bytes_written, NULL);

    p.output_mode = BT_OUTPUT_FILE;
    p.output_style = BT_OUTPUT_MEDIUM;
    p.outfile = logfile;

    c.context = ep->ContextRecord;
    c.exception_record = ep->ExceptionRecord;

    if (describe_exception) {
        describe_exception(&p, &c);
        WriteFile(logfile, "\r\n", 2, &bytes_written, NULL);
    }

    if (get_backtrace) {
        get_backtrace(&p, &c);
        WriteFile(logfile, "\r\n", 2, &bytes_written, NULL);
    }

#if DIAG_PLATFORM_WINDOWS
    logdata = thread_logdata;
#else
    logdata = global_logdata;
#endif

    if (logdata) {
        WriteFile(logfile, logdata, strlen(logdata), &bytes_written,
                  NULL);
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

static int count_header_log_length(void *user_data, const char *key, const char *value)
{
    apr_size_t *count = user_data;

    *count += strlen(key) + strlen(":") + strlen(value) + strlen(END_OF_LINE);

    return 1;
}

typedef struct {
    char *outch;
    char *lastoutch;
} copy_header_user_data_t;

static int copy_headers(void *user_data, const char *key, const char *value)
{
    copy_header_user_data_t *chud = user_data;

    chud->outch = add_string(chud->outch, chud->lastoutch, key, NULL);
    chud->outch = add_string(chud->outch, chud->lastoutch, ":", NULL);
    chud->outch = add_string(chud->outch, chud->lastoutch, value, NULL);
    chud->outch = add_string(chud->outch, chud->lastoutch, END_OF_LINE, NULL);

    return 1;
}

static apr_status_t clear_request_logdata(void *unused)
{
#if DIAG_PLATFORM_WINDOWS
    thread_logdata = NULL;
#else
    global_logdata = NULL;
#endif
    return APR_SUCCESS;
}

/* This follows mod_log_forensic's post-read-request hook.
 */
static int whatkilledus_post_read_request(request_rec *r)
{
    apr_size_t count;
    char *logdata;
    copy_header_user_data_t chud = {0};

    if (r->prev) {
        return DECLINED;
    }

    /* prepare the request report for the potential crash, ready to write to 
     * the log file handle
     */
    count = 0;
    count += strlen("Request line:" END_OF_LINE);
    count += strlen(r->the_request);
    count += strlen(END_OF_LINE);
    count += strlen("Request headers:" END_OF_LINE);
    apr_table_do(count_header_log_length, &count, r->headers_in, NULL);
    count += strlen(END_OF_LINE);
    count += 1; /* terminating '\0' */

    logdata = apr_palloc(r->pool, count);

    chud.outch = logdata;
    chud.lastoutch = logdata + count - 1;

    chud.outch = add_string(chud.outch, chud.lastoutch, "Request line:" END_OF_LINE, NULL);
    chud.outch = add_string(chud.outch, chud.lastoutch, r->the_request, NULL);
    chud.outch = add_string(chud.outch, chud.lastoutch, END_OF_LINE, NULL);
    chud.outch = add_string(chud.outch, chud.lastoutch, "Request headers:" END_OF_LINE, NULL);
    /* insert headers */
    apr_table_do(copy_headers, &chud, r->headers_in, NULL);
    chud.outch = add_string(chud.outch, chud.lastoutch, END_OF_LINE, NULL);

#if DIAG_PLATFORM_WINDOWS
    thread_logdata = logdata;
#else
    global_logdata = logdata;
#endif

    apr_pool_cleanup_register(r->pool, NULL,
                              clear_request_logdata, apr_pool_cleanup_null);

    return OK;
}

static void whatkilledus_optional_fn_retrieve(void)
{
    describe_exception = APR_RETRIEVE_OPTIONAL_FN(backtrace_describe_exception);
    get_backtrace = APR_RETRIEVE_OPTIONAL_FN(backtrace_get_backtrace);
}

static apr_status_t whatkilledus_child_term(void *unused)
{
#if DIAG_PLATFORM_WINDOWS
    if (old_exception_filter) {
        SetUnhandledExceptionFilter(old_exception_filter);
        old_exception_filter = NULL;
    }
#endif
    return APR_SUCCESS;
}

static void whatkilledus_child_init(apr_pool_t *p, server_rec *s)
{
    main_server = s;

#if DIAG_PLATFORM_WINDOWS
    /* must back this out before this DLL is unloaded;
     * but previous exception filter might have been unloaded too
     */
    old_exception_filter = SetUnhandledExceptionFilter(whatkilledus_crash_handler);
#endif

    apr_pool_cleanup_register(p, NULL,
                              whatkilledus_child_term, apr_pool_cleanup_null);
}

static void banner(server_rec *s)
{
    const char *userdata_key = "whatkilledus_banner";
    void *data;

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (data) {
        return;
    }

    apr_pool_userdata_set((const void *)1, userdata_key,
                          apr_pool_cleanup_null, s->process->pool);

#if DIAG_PLATFORM_WINDOWS
    if (getenv("AP_PARENT_PID")) {
        /* don't repeat the message in child processes */
        return;
    }
#endif
    /* In the event that you find this message distasteful or otherwise
     * inappropriate for your users to view, please contact 
     * info@emptyhammock.com about a business arrangement whereby
     * you are provided with a lightly customized version for your
     * product and, more importantly, confirming proper operation with
     * your product is part of the normal release testing procedures
     * for this module.
     */
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_whatkilledus v%s from http://emptyhammock.com/",
                 DIAG_MOD_VERSION);
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

    banner(s);
    logfilename = ap_server_root_relative(pconf, DEFAULT_REL_LOGFILENAME);

    return OK;
}

static void whatkilledus_register_hooks(apr_pool_t *p)
{
#if DIAG_PLATFORM_UNIX
    ap_hook_fatal_exception(whatkilledus_fatal_exception, NULL, NULL,
                            APR_HOOK_MIDDLE);
#endif
    ap_hook_optional_fn_retrieve(whatkilledus_optional_fn_retrieve, NULL, NULL,
                                 APR_HOOK_MIDDLE);
    ap_hook_post_config(whatkilledus_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(whatkilledus_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(whatkilledus_post_read_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
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
