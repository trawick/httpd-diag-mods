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

#include "apr_strings.h"

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

#ifndef WKU_USE_PTHREAD_SPECIFIC
#if DIAG_PLATFORM_MACOSX
#define WKU_USE_PTHREAD_SPECIFIC 1
#else
#define WKU_USE_PTHREAD_SPECIFIC 0
#endif
#endif

#if WKU_USE_PTHREAD_SPECIFIC
#include <pthread.h>
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

typedef struct whatkilledus_server_t {
    apr_array_header_t *obscured;
} whatkilledus_server_t;

module AP_MODULE_DECLARE_DATA whatkilledus_module;

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

#if WKU_USE_PTHREAD_SPECIFIC
static pthread_key_t *thread_logdata_key;
#elif DIAG_PLATFORM_WINDOWS
static __declspec(thread) const char *thread_logdata;
#else
static __thread const char *thread_logdata;
#endif

/* contents of test_char.h */

/* this file is automatically generated by gen_test_char, do not edit */
#define T_ESCAPE_SHELL_CMD     (1)
#define T_ESCAPE_PATH_SEGMENT  (2)
#define T_OS_ESCAPE_PATH       (4)
#define T_HTTP_TOKEN_STOP      (8)
#define T_ESCAPE_LOGITEM       (16)
#define T_ESCAPE_FORENSIC      (32)
#define T_ESCAPE_URLENCODED    (64)

static const unsigned char test_char_table[256] = {
    32,126,126,126,126,126,126,126,126,126,127,126,126,127,126,126,126,126,126,126,
    126,126,126,126,126,126,126,126,126,126,126,126,14,64,95,70,65,103,65,65,
    73,73,1,64,72,0,0,74,0,0,0,0,0,0,0,0,0,0,104,79,
    79,72,79,79,72,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,79,95,79,71,0,71,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,79,103,79,65,126,118,118,118,118,118,118,118,118,118,118,118,118,
    118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,
    118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,
    118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,
    118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,
    118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,
    118,118,118,118,118,118,118,118,118,118,118,118,118,118,118,118 
};

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

/* This is the equivalent of log_scape() in mod_log_forensic. */
static char *add_escaped_string(char *outch, const char *lastoutch,
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
        if (test_char_table[*(unsigned char *)inch] & T_ESCAPE_FORENSIC) {
            /* need four characters */
            if (outch + 3 > lastoutch) {
                break;
            }
            *outch = '%';
            outch += 1;
            apr_snprintf(outch, 3, "%02x", *(unsigned char *)inch);
            outch += 2;
        }
        else {
            *outch = *inch;
            ++outch;
        }
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

static void *create_whatkilledus_server_conf(apr_pool_t *p, server_rec *s)
{
    whatkilledus_server_t *conf;

    conf = (whatkilledus_server_t *)apr_pcalloc(p, sizeof(whatkilledus_server_t));

    return conf;
}

static void *merge_whatkilledus_server_conf(apr_pool_t *p, void *basev, void *overridesv)
{
    whatkilledus_server_t *base = (whatkilledus_server_t *)basev;
    whatkilledus_server_t *overrides = (whatkilledus_server_t *)overridesv;
    whatkilledus_server_t *conf = (whatkilledus_server_t *)apr_pmemdup(p, base, sizeof(*conf));

    return conf; /* no overrides currently */
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
typedef HANDLE file_handle_t;

static void write_file(HANDLE logfile,
                       const char *buf,
                       size_t buflen)
{
    DWORD bytes_written;

    WriteFile(logfile, buf, buflen, &bytes_written, NULL);
}
#else
typedef int file_handle_t;
    
static void write_file(int logfile,
                       const char *buf,
                       size_t buflen)
{
    write(logfile, buf, buflen);
}
#endif

static void write_report(file_handle_t logfile,
                         bt_param_t *p,
                         diag_context_t *c,
                         const char *heading,
                         const char *logdata)
{
    p->output_mode = BT_OUTPUT_FILE;
    p->output_style = BT_OUTPUT_MEDIUM;
    p->outfile = logfile;

    write_file(logfile, heading, strlen(heading));
    write_file(logfile, END_OF_LINE, strlen(END_OF_LINE));

    if (describe_exception) {
        describe_exception(p, c);
        write_file(logfile, END_OF_LINE, strlen(END_OF_LINE));
    }

    if (get_backtrace) {
#if DIAG_PLATFORM_WINDOWS
        get_backtrace(p, c);
#else
        get_backtrace(p, NULL);
#endif
        write_file(logfile, END_OF_LINE, strlen(END_OF_LINE));
    }

    if (logdata) {
        write_file(logfile, logdata, strlen(logdata));
    }

    write_file(logfile, END_OF_LINE, strlen(END_OF_LINE));
}

#if DIAG_PLATFORM_WINDOWS

static LONG WINAPI whatkilledus_crash_handler(EXCEPTION_POINTERS *ep)
{
    bt_param_t p = {0};
    diag_context_t c = {0};
    HANDLE logfile;
    SYSTEMTIME now;
    char buf[128];
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

    c.context = ep->ContextRecord;
    c.exception_record = ep->ExceptionRecord;

#if WKU_USE_PTHREAD_SPECIFIC
    if (thread_logdata_key) {
        logdata = pthread_getspecific(*thread_logdata_key);
    }
    else {
        logdata = NULL;
    }
#else
    logdata = thread_logdata;
#endif

    write_report(logfile, &p, &c, buf, logdata);

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
    const char *logdata;

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
    c.signal = ei->sig;

#if WKU_USE_PTHREAD_SPECIFIC
    if (thread_logdata_key) {
        logdata = pthread_getspecific(*thread_logdata_key);
    }
    else {
        logdata = NULL;
    }
#else
    logdata = thread_logdata;
#endif

    write_report(logfile, &p, &c, buf, logdata);

    close(logfile);

    return OK;
}

#endif

/* count_string() copied from httpd 2.4's mod_log_forensic
 * for mod_whatkilledus, this provides an upper bound on the length
 * of the data to be logged (some such data may be obliterated first)
 */
static int count_string(const char *p)
{
    int n;

    for (n = 0 ; *p ; ++p, ++n)
        if (test_char_table[*(unsigned char *)p]&T_ESCAPE_FORENSIC)
            n += 2;
    return n;
}

static int count_header_log_length(void *user_data, const char *key, const char *value)
{
    apr_size_t *count = user_data;

    *count += count_string(key) + strlen(":") + count_string(value) + strlen(END_OF_LINE);

    return 1;
}

typedef struct {
    char *outch;
    char *lastoutch;
    apr_array_header_t *obscured;
} copy_header_user_data_t;

static int copy_headers(void *user_data, const char *key, const char *value)
{
    copy_header_user_data_t *chud = user_data;
    int obscure_value = 0;

    chud->outch = add_escaped_string(chud->outch, chud->lastoutch, key, NULL);
    chud->outch = add_string(chud->outch, chud->lastoutch, ":", NULL);

    if (chud->obscured) {
        int i;
        for (i = 0; i < chud->obscured->nelts; i++) {
            if (!strcasecmp(key, APR_ARRAY_IDX(chud->obscured, i, char *))) {
                obscure_value = 1;
                break;
            }
        }
    }

    if (obscure_value) {
        size_t len = strlen(value);

        while (len > 0) {
            chud->outch = add_string(chud->outch, chud->lastoutch, "*", NULL);
            len--;
        }
    }
    else {
        chud->outch = add_escaped_string(chud->outch, chud->lastoutch, value, NULL);
    }
    chud->outch = add_string(chud->outch, chud->lastoutch, END_OF_LINE, NULL);

    return 1;
}

static apr_status_t clear_request_logdata(void *unused)
{
#if WKU_USE_PTHREAD_SPECIFIC
    if (thread_logdata_key) {
        pthread_setspecific(*thread_logdata_key, NULL);
    }
#else
    thread_logdata = NULL;
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
    whatkilledus_server_t *conf = ap_get_module_config(r->server->module_config,
                                                       &whatkilledus_module);

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
    chud.obscured = conf->obscured;
    apr_table_do(copy_headers, &chud, r->headers_in, NULL);

#if WKU_USE_PTHREAD_SPECIFIC
    if (thread_logdata_key) {
        pthread_setspecific(*thread_logdata_key, logdata);
    }
#else
    thread_logdata = logdata;
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

#if WKU_USE_PTHREAD_SPECIFIC
    thread_logdata_key = malloc(sizeof *thread_logdata_key);
    if (pthread_key_create(thread_logdata_key, NULL) != 0) {
        free(thread_logdata_key);
        thread_logdata_key = NULL;
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                     LOG_PREFIX "pthread_key_create() failed, request information "
                     "won't be present in crash reports");
    }
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

static const char *set_obscured_headers(cmd_parms *cmd, void *dummy, const char *arg)
{
    whatkilledus_server_t *conf = ap_get_module_config(cmd->server->module_config,
                                                       &whatkilledus_module);
    void *new_entry;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (!conf->obscured) {
        conf->obscured = apr_array_make(cmd->pool, 10, sizeof(char *));
    }

    new_entry = apr_array_push(conf->obscured);
    *(char **)new_entry = apr_pstrdup(cmd->pool, arg);

    return NULL;
}

static const command_rec whatkilledus_cmds[] =
{
#if DIAG_PLATFORM_UNIX
    AP_INIT_TAKE1("EnableExceptionHook", check_exception_hook, NULL, RSRC_CONF,
                  "Check if EnableExceptionHook is On"),
#endif
    AP_INIT_ITERATE("WhatkilledusObscuredHeaders", set_obscured_headers, NULL,
                    RSRC_CONF,
                    "List request headers whose values should be obscured in the log"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA whatkilledus_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_whatkilledus_server_conf,
    merge_whatkilledus_server_conf,
    whatkilledus_cmds,
    whatkilledus_register_hooks
};
