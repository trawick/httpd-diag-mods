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

#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "ap_mmn.h"

#include "mod_backtrace.h"

#include "diag_mod_version.h"

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

#if DIAG_PLATFORM_UNIX
#define END_OF_LINE "\n"
#else
#define END_OF_LINE "\r\n"
#endif

module AP_MODULE_DECLARE_DATA backtrace_module;
static server_rec *main_server;
#if DIAG_PLATFORM_WINDOWS
static const char *configured_symbol_path;
#endif

typedef struct backtrace_server_t {
#if MODBT_HAVE_ERRORLOG_HOOK
    int enabled;
    const char *str;
    int oserror;
    apr_status_t error;
#else
    int dummy;
#endif
} backtrace_server_t;

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

static void *create_backtrace_server_conf(apr_pool_t *p, server_rec *s)
{
    backtrace_server_t *conf;

    conf = (backtrace_server_t *)apr_pcalloc(p, sizeof(backtrace_server_t));
#if MODBT_HAVE_ERRORLOG_HOOK
    conf->enabled = -1;
#endif
    return conf;
}

static void *merge_backtrace_server_conf(apr_pool_t *p, void *basev, void *overridesv)
{
    backtrace_server_t *base = (backtrace_server_t *)basev;
#if MODBT_HAVE_ERRORLOG_HOOK
    backtrace_server_t *overrides = (backtrace_server_t *)overridesv;
#endif
    backtrace_server_t *conf = (backtrace_server_t *)apr_pmemdup(p, base, sizeof(*conf));

#if MODBT_HAVE_ERRORLOG_HOOK
    if (overrides->enabled != -1) {
        conf->enabled = overrides->enabled;
        conf->str = overrides->str;
        conf->oserror = overrides->oserror;
        conf->error = overrides->error;
    }
#endif

    return conf;
}

static void fmt2(void *user_data, const char *s)
{
    bt_param_t *p = user_data;

    switch(p->output_mode) {
    case BT_OUTPUT_BUFFER:
        if (strlen(s) + strlen(p->buffer) + 1 < p->buffer_size) {
            strcat(p->buffer, s);
        }
        break;
    case BT_OUTPUT_FILE:
        write_file(p->outfile, s, strlen(s));
        write_file(p->outfile, END_OF_LINE, strlen(END_OF_LINE));
        break;
    default: /* should be BT_OUTPUT_ERROR_LOG: */
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, main_server,
                     LOG_PREFIX "%s", s);
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

static int backtrace_get_backtrace(bt_param_t *p, diag_context_t *c)
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
    return diag_backtrace(&o, &dp, c);
}

typedef struct {
    int kept;
    int to_keep;
    char *buffer;
    size_t len;
} loginfo_t;

static void fmt(void *user_data, const char *s)
{
    loginfo_t *li = user_data;

    if (li->kept >= li->to_keep) {
        return;
    }

    if (s[0] == 'a'
        && s[1] == 'p'
        && s[2] == '_') {
        if (s[3] == 'l'
            && s[4] == 'o'
            && s[5] == 'g'
            && s[6] == '_') {
            li->kept = 0;
            li->buffer[0] = '\0';
            return;
        }
        else if (!strcmp(s + 3, "run_error_log")) {
            li->kept = 0;
            li->buffer[0] = '\0';
            return;
        }
#if DIAG_PLATFORM_FREEBSD
        else if (!strcmp(s + 3, "error_log2stderr")) {
            /* with httpd 2.2.x, this function right before
             * log_error_core() may be the symbol retrieved
             */
            li->kept = 0;
            li->buffer[0] = '\0';
            return;
        }
#endif
    }

    if (!memcmp(s, "SKIP_", 5)) {
        li->kept = 0;
        li->buffer[0] = '\0';
        return;
    }

    if (!strcmp(s, "log_error_core")) {
        li->kept = 0;
        li->buffer[0] = '\0';
        return;
    }

#if DIAG_PLATFORM_FREEBSD
    if (!strcmp(s, "_init")) {
        return;
    }
#endif

    if (!strcmp(s, "main")
#if DIAG_PLATFORM_WINDOWS
        || !strcmp(s, "BaseThreadInitThunk")
#endif
        ) {
        /* keep this, but we're done */
        li->kept = li->to_keep;
    }
    else {
        li->kept++;
    }

    if (strlen(li->buffer) + strlen(s) < li->len) {
        strcat(li->buffer, s);
        if (strlen(li->buffer) < li->len) {
            strcat(li->buffer, "<");
        }
    }
}

static void SKIP_mini_backtrace(char *buf, int buflen, int to_keep)
{
    diag_output_t o = {0};
    diag_backtrace_param_t p = {0};
    loginfo_t li = {0};

    li.to_keep = to_keep;
    li.buffer = buf;
    li.len = buflen;

    o.user_data = &li;
    o.output_mode = DIAG_CALL_FN;
    o.output_fn = fmt;

    p.symbols_initialized = 1;
    p.backtrace_fields = DIAG_BTFIELDS_FUNCTION;
    p.backtrace_count = to_keep + 7;

    if (diag_backtrace(&o, &p, NULL) == 0) {
        if (buf[strlen(buf) - 1] == '<') {
            buf[strlen(buf) - 1] = '\0';
        }
    }
    else {
        buf[0] = '\0';
    }
}

#if MODBT_HAVE_ERRORLOG_HANDLER
static int SKIP_backtrace_log(const ap_errorlog_info *info,
                              const char *arg, char *buf, int buflen)
{
    int log = 0;

    if (arg) {
        if (arg[0] == '/' && arg[strlen(arg) - 1] == '/') {
            char searchbuf[128];

            apr_cpystrn(searchbuf, arg + 1, sizeof searchbuf);
            searchbuf[strlen(searchbuf) - 1] = '\0';
            if (ap_strstr_c(info->format, searchbuf) != NULL) {
                log = 1;
            }
        }
        else if (!memcmp(arg, "error==", 7)) {
            if (atoi(arg + 7) == info->status) {
                log = 1;
            }
        }
        else if (!memcmp(arg, "oserror==", 9)) {
            if (atoi(arg + 9) == info->status - APR_OS_START_SYSERR) {
                log = 1;
            }
        }
        else {
            apr_cpystrn(buf, "unrecognized fmt", buflen);
            return strlen(buf);
        }
    }

    if (log) {
        SKIP_mini_backtrace(buf, buflen, 5);
        return strlen(buf);
    }
    else {
        return 0;
    }
}
#endif /* MODBT_HAVE_ERRORLOG_HANDLER */

#if MODBT_HAVE_ERRORLOG_HOOK
static void SKIP_backtrace_error_log(const char *file, int line,
                                     int level, apr_status_t status, 
                                     const server_rec *s, const request_rec *r,
                                     apr_pool_t *pool, const char *errstr)
{
    static const char *label = LOG_PREFIX;
    backtrace_server_t *conf;
    char buf[256];

    if (!s) {
        s = main_server;
    }

    if (!s) {
        return;
    }

    conf = ap_get_module_config(s->module_config,
                                &backtrace_module);

    if (!conf || !conf->enabled) {
        return;
    }

    if (!errstr) {
        /* ??? */
        return;
    }

    if (ap_strstr_c(errstr, label)) {
        /* recursive call */
        return;
    }

    if (conf->error != 0 && conf->error != status) {
        return;
    }

    if (conf->oserror != 0 && status - APR_OS_START_SYSERR != conf->oserror) {
        return;
    }

    if (conf->str && !ap_strstr_c(errstr, conf->str)) {
        return;
    }

    buf[0] = '\0';
    SKIP_mini_backtrace(buf, sizeof buf, 5);
    if (r) {
        ap_log_rerror(APLOG_MARK, level, 0, r,
                      "%s%s", label, buf);
    }
    else if (s) {
        ap_log_error(APLOG_MARK, level, 0, s,
                     "%s%s", label, buf);
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
    int rc = 0;

    p.symbols_initialized = 1;
    p.backtrace_count = 10;
    o.user_data = r;
    o.output_mode = DIAG_CALL_FN;
    o.output_fn = fmt_rputs;

    ap_set_content_type(r, "text/plain");

#define TESTCASE(btfields)                         \
    ap_rputs("----------------------------------------------------\n", r); \
    ap_rputs("mod_backtrace: " #btfields "\n", r); \
    p.backtrace_fields = (btfields);               \
    rc += diag_backtrace(&o, &p, NULL)

    TESTCASE(DIAG_BTFIELDS_MODULE_PATH);
    TESTCASE(DIAG_BTFIELDS_MODULE_NAME);
    TESTCASE(DIAG_BTFIELDS_MODULE_PATH | DIAG_BTFIELDS_MODULE_NAME);
    TESTCASE(DIAG_BTFIELDS_FUNCTION);
    TESTCASE(DIAG_BTFIELDS_FN_OFFSET);
    TESTCASE(DIAG_BTFIELDS_FUNCTION | DIAG_BTFIELDS_FN_OFFSET);
    TESTCASE(DIAG_BTFIELDS_ADDRESS);
    TESTCASE(DIAG_BTFIELDS_ADDRESS | DIAG_BTFIELDS_FUNCTION | DIAG_BTFIELDS_FN_OFFSET);

    if (rc) {
        ap_rputs("\nSome call to mod_backtrace failed!\n", r);
    }
}

static int backtrace_handler(request_rec *r)
{
    if (!strcmp(r->handler, "backtrace-handler")) {
        backtrace(r);
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      /* no LOG_PREFIX */ "---MoD_bAcKtRaCe---");
        /* If this has LOG_PREFIX, the regression test configuration won't
         * result in a backtrace for this message.
         */
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
                     LOG_PREFIX "Symbol path set to %s", symbolpath);
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

static void banner(server_rec *s)
{
    const char *userdata_key = "backtrace_banner";
    void *data;
#if DIAG_HAVE_LIBUNWIND_BACKTRACE
    const char *impl = "(using libunwind)";
#else
    const char *impl = "";
#endif

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
                 "mod_backtrace v%s from http://emptyhammock.com/ %s",
                 DIAG_MOD_VERSION, impl);
}

static int backtrace_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    banner(s);
    return OK;
}

static void backtrace_register_hooks(apr_pool_t *p)
{
#if MODBT_HAVE_ERRORLOG_HANDLER
    ap_register_errorlog_handler(p, "B", SKIP_backtrace_log, 0);
#endif
#if MODBT_HAVE_ERRORLOG_HOOK
    ap_hook_error_log(SKIP_backtrace_error_log, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    ap_hook_handler(backtrace_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(backtrace_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(backtrace_post_config, NULL, NULL, APR_HOOK_MIDDLE);
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

#if MODBT_HAVE_ERRORLOG_HOOK
static const char *set_error_logging(cmd_parms *cmd, void *dummy, const char *arg)
{
    backtrace_server_t *conf = ap_get_module_config(cmd->server->module_config,
                                                    &backtrace_module);

    if (!strcasecmp(arg, "off")) {
        conf->enabled = 0;
    }
    else if (!strcasecmp(arg, "on")) {
        conf->enabled = 1;
    }
    else {
        conf->enabled = 1;
        if (arg[0] == '/' && arg[strlen(arg) - 1] == '/') {
            conf->str = apr_pstrndup(cmd->pool, arg + 1, strlen(arg) - 2);
        }
        else if (!memcmp(arg, "error==", 7)) {
            conf->error = atoi(arg + 7);
        }
        else if (!memcmp(arg, "oserror==", 9)) {
            conf->oserror = atoi(arg + 9);
        }
        else {
            return apr_pstrcat(cmd->pool, "Invalid value for BacktraceErrorLogging: ",
                               arg, NULL);
        }
    }
    return NULL;
}
#endif

static const command_rec backtrace_cmds[] =
{
#if DIAG_PLATFORM_WINDOWS
    AP_INIT_TAKE1("BacktraceSymbolPath", set_symbol_path, NULL, RSRC_CONF,
                  "Specify additional directories for symbols (e.g., BacktraceSymbolPath c:/dir1;c:/dir2;c:/dir3)"),
#endif
#if MODBT_HAVE_ERRORLOG_HOOK
    AP_INIT_TAKE1("BacktraceErrorLogging", set_error_logging, NULL, RSRC_CONF,
                  "Specify conditions for adding a backtrace to the error log"),
#endif
    {NULL}
};

module AP_MODULE_DECLARE_DATA backtrace_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_backtrace_server_conf,
    merge_backtrace_server_conf,
    backtrace_cmds,
    backtrace_register_hooks,
};
