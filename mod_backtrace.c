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

#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "ap_mmn.h"

#include "mod_backtrace.h"

#if DIAG_PLATFORM_UNIX
#include <unistd.h>
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
APLOG_USE_MODULE(backtrace);
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
#define MODBT_HAVE_ERRORLOG_HANDLER 1
#define MODBT_HAVE_ERRORLOG_HOOK    0
#else
#define MODBT_HAVE_ERRORLOG_HANDLER 0
#define MODBT_HAVE_ERRORLOG_HOOK    1
#endif

/* Use this LOG_PREFIX only on non-debug messages.  This provides a module
 * identifer with httpd < 2.4.
 */
#if AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
#define LOG_PREFIX ""
#else
#define LOG_PREFIX "mod_backtrace: "
#endif

static server_rec *main_server;
#if DIAG_PLATFORM_WINDOWS
static const char *configured_symbol_path;
#endif

static void fmt2(void *user_data, const char *s)
{
    bt_param_t *p = user_data;
    
    switch(p->output_mode) {
    case BT_OUTPUT_BUFFER:
        if (strlen(s) + strlen(p->buffer) + 1 < p->buffer_size) {
            strcat(p->buffer, s);
            strcat(p->buffer, "\n");
        }
        break;
    case BT_OUTPUT_FILE:
#if DIAG_PLATFORM_WINDOWS
        WriteFile(p->outfile, s, strlen(s), NULL, NULL);
#else
        write(p->outfile, s, strlen(s));
        write(p->outfile, "\n", 1);
#endif
        break;
    default: /* should be BT_OUTPUT_ERROR_LOG: */
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, main_server,
                     "%s", s);
        break;
    }
}

static void init_diag_output(bt_param_t *p, diag_output_t *o)
{
    /* simple case, handled by diag_backtrace() directly */
    if (p->output_mode == BT_OUTPUT_FILE &&
        p->output_style == BT_OUTPUT_LONG) {
        o->output_mode = DIAG_WRITE_FD;
        o->outfile = p->outfile;
    }
    else if (p->output_mode == BT_OUTPUT_FN) {
        o->output_mode = DIAG_CALL_FN;
        o->output_fn = p->output_fn;
        o->user_data = p->user_data;
    }
    else {
        if (p->output_mode == BT_OUTPUT_BUFFER) {
            p->buffer[0] = '\0';
        }

        o->output_mode = DIAG_CALL_FN;
        o->output_fn = fmt2;
        o->user_data = p;
    }
}

static void backtrace_describe_exception(bt_param_t *p, diag_context_t *c)
{
    diag_output_t o = {0};

    init_diag_output(p, &o);
    diag_describe(&o, c);
}

static void backtrace_get_backtrace(bt_param_t *p, diag_context_t *c)
{
    diag_backtrace_param_t dp = {0};
    diag_output_t o = {0};

    dp.symbols_initialized = 1;
    dp.backtrace_count = p->backtrace_count;

    switch (p->output_mode) {
    case BT_OUTPUT_SHORT:
        dp.backtrace_fields = DIAG_BTFIELDS_FUNCTION;
        break;
    case BT_OUTPUT_MEDIUM:
        dp.backtrace_fields = DIAG_BTFIELDS_FUNCTION
            | DIAG_BTFIELDS_FN_OFFSET;
        break;
    default:
        dp.backtrace_fields = DIAG_BTFIELDS_ALL;
    }
    
    init_diag_output(p, &o);
    diag_backtrace(&o, &dp, c);
}

typedef struct {
    int skip;
    char *buffer;
    size_t len;
} loginfo_t;

static void fmt(void *user_data, const char *s)
{
    loginfo_t *li = user_data;

    if (li->skip > 0) {
        --li->skip;
        return;
    }

    if (strlen(li->buffer) + strlen(s) < li->len) {
        strcat(li->buffer, s);
        strcat(li->buffer, "<");
    }
}

static void mini_backtrace(char *buf, int buflen, int skip)
{
    diag_output_t o = {0};
    diag_backtrace_param_t p = {0};
    loginfo_t li = {0};

    li.skip = skip;
    li.buffer = buf;
    li.len = buflen;

    o.user_data = &li;
    o.output_mode = DIAG_CALL_FN;
    o.output_fn = fmt;

    p.symbols_initialized = 1;
    p.backtrace_fields = DIAG_BTFIELDS_FUNCTION;
    p.backtrace_count = skip + 4;

    diag_backtrace(&o, &p, NULL);
    if (buf[strlen(buf) - 1] == '<') {
        buf[strlen(buf) - 1] = '\0';
    }
}

#if MODBT_HAVE_ERRORLOG_HANDLER
static int backtrace_log(const ap_errorlog_info *info,
                         const char *arg, char *buf, int buflen)
{
    mini_backtrace(buf, buflen, 1);
    return strlen(buf);
}
#endif /* MODBT_HAVE_ERRORLOG_HANDLER */

#if MODBT_HAVE_ERRORLOG_HOOK
static void backtrace_error_log(const char *file, int line,
                                int level, apr_status_t status, 
                                const server_rec *s, const request_rec *r,
                                apr_pool_t *pool, const char *errstr)
{
    static const char *label = "Backtrace:";

    if (errstr && (r || s) && !strstr(errstr, label)) {
        char buf[128];

        buf[0] = '\0';
        mini_backtrace(buf, sizeof buf, 5);
        if (r) {
            ap_log_rerror(APLOG_MARK, level, 0, r,
                          "%s %s", label, buf);
        }
        else if (s) {
            ap_log_error(APLOG_MARK, level, 0, s,
                         "%s %s", label, buf);
        }
    }
}
#endif /* MODBT_HAVE_ERRORLOG_HOOK */

static void fmt_rputs(void *userdata, const char *buffer)
{
    request_rec *r = userdata;

    ap_rputs(buffer, r);
    ap_rputs("\n", r);
}

static void backtrace(request_rec *r)
{
    diag_backtrace_param_t p = {0};
    diag_output_t o = {0};

    p.symbols_initialized = 1;

    ap_set_content_type(r, "text/plain");

    ap_rputs("========== mod_backtrace report ===========================\n", r);

    o.user_data = r;
    o.output_mode = DIAG_CALL_FN;
    o.output_fn = fmt_rputs;
    p.backtrace_fields = DIAG_BTFIELDS_FUNCTION;
    p.backtrace_count = 10;
    diag_backtrace(&o, &p, NULL);
}

static int backtrace_handler(request_rec *r)
{
    if (!strcmp(r->handler, "backtrace-handler")) {
        backtrace(r);
        return OK;
    }

    return DECLINED;
}

#if DIAG_PLATFORM_WINDOWS

static void load_symbols(apr_pool_t *p, server_rec *s)
{
    const char *bindir = ap_server_root_relative(p, "bin");
    const char *modulesdir = ap_server_root_relative(p, "modules");
    const char *symbolpath = getenv("_NT_ALT_SYMBOL_PATH");
    apr_finfo_t finfo;

    if (!symbolpath) {
        symbolpath = getenv("_NT_SYMBOL_PATH");
    }

    symbolpath = apr_pstrcat(p,
                             configured_symbol_path ? configured_symbol_path : "",
                             configured_symbol_path ? ";" : "",
                             bindir, ";", modulesdir, ";", symbolpath /* may be NULL */,
                             ";", NULL);

    if (SymInitialize(GetCurrentProcess(),
                      symbolpath,
                      TRUE) != TRUE) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, APR_FROM_OS_ERROR(GetLastError()), s,
                     LOG_PREFIX "SymInitialize() failed");
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "Symbol path set to %s", symbolpath);
    }

    if (apr_stat(&finfo, ap_server_root_relative(p, "bin/httpd.pdb"), APR_FINFO_MIN, p)
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     LOG_PREFIX "Symbol files are not present in the server bin directory; "
                     "backtraces may not have symbols");
    }
}

#else /* WIN32 */

static void load_symbols(apr_pool_t *p, server_rec *s)
{
}

#endif /* WIN32 */

static void backtrace_child_init(apr_pool_t *p, server_rec *s)
{
    main_server = s;

    load_symbols(p, s);
    diag_backtrace_init(1);
}

static void backtrace_register_hooks(apr_pool_t *p)
{
#if MODBT_HAVE_ERRORLOG_HANDLER
    ap_register_errorlog_handler(p, "B", backtrace_log, 0);
#endif
#if MODBT_HAVE_ERRORLOG_HOOK
    ap_hook_error_log(backtrace_error_log, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    ap_hook_handler(backtrace_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(backtrace_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    APR_REGISTER_OPTIONAL_FN(backtrace_describe_exception);
    APR_REGISTER_OPTIONAL_FN(backtrace_get_backtrace);
}

#if DIAG_PLATFORM_WINDOWS
static const char *set_symbol_path(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    configured_symbol_path = arg;
    return NULL;
}
#endif

static const command_rec backtrace_cmds[] =
{
#if DIAG_PLATFORM_WINDOWS
    AP_INIT_TAKE1("BacktraceSymbolPath", set_symbol_path, NULL, RSRC_CONF,
                  "Specify additional directoriess for symbols (e.g., BacktraceSymbolPath c:/dir1;c:/dir2;c:/dir3)"),
#endif
    {NULL}
};

module AP_MODULE_DECLARE_DATA backtrace_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    backtrace_cmds,
    backtrace_register_hooks,
};
