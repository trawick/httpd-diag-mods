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

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "ap_mmn.h"

#include "mod_backtrace.h"

#ifndef WIN32
#include <unistd.h>
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
APLOG_USE_MODULE(backtrace);
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
#define DIAG_HAVE_ERRORLOG_HANDLER 1
#else
#define DIAG_HAVE_ERRORLOG_HANDLER 0
#endif

static server_rec *main_server;

static void backtrace_describe_exception(diag_param_t *p)
{
    diag_describe(p);
}

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
#ifdef WIN32
        XXX
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

static void backtrace_get_backtrace(bt_param_t *p)
{
    diag_param_t dp = {0};

    dp.calling_context = DIAG_MODE_NORMAL;
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
    
    /* simple case, handled by diag_backtrace() directly */
    if (p->output_mode == BT_OUTPUT_FILE &&
        p->output_style == BT_OUTPUT_LONG) {
        dp.output_mode = DIAG_WRITE_FD;
        dp.outfile = p->outfile;
    }
    else if (p->output_mode == BT_OUTPUT_FN) {
        dp.output_mode = DIAG_CALL_FN;
        dp.output_fn = p->output_fn;
        dp.user_data = p->user_data;
    }
    else {
        if (p->output_mode == BT_OUTPUT_BUFFER) {
            p->buffer[0] = '\0';
        }

        dp.output_mode = DIAG_CALL_FN;
        dp.output_fn = fmt2;
        dp.user_data = p;
    }
    
    diag_backtrace(&dp);
}

#if DIAG_HAVE_ERRORLOG_HANDLER
typedef struct {
    char *buffer;
    size_t len;
} loginfo_t;

static void fmt(void *user_data, const char *s)
{
    loginfo_t *li = user_data;

    if (strlen(li->buffer) + strlen(s) < li->len) {
        strcat(li->buffer, s);
        strcat(li->buffer, "<");
    }
}

static int backtrace_log(const ap_errorlog_info *info,
                         const char *arg, char *buf, int buflen)
{
    diag_param_t p = {0};
    loginfo_t li = {0};

    li.buffer = buf;
    li.len = buflen;

    p.calling_context = DIAG_MODE_NORMAL;
    p.outfile = 2;
    p.output_mode = DIAG_WRITE_FD;
    diag_backtrace(&p);

    memset(&p, 0, sizeof p);
    p.user_data = &li;
    p.calling_context = DIAG_MODE_NORMAL;
    p.output_mode = DIAG_CALL_FN;
    p.backtrace_fields = DIAG_BTFIELDS_FUNCTION;
    p.backtrace_count = 3;
    p.output_fn = fmt;
    diag_backtrace(&p);
    if (buf[strlen(buf) - 1] == '<') {
        buf[strlen(buf) - 1] = '\0';
    }

    return strlen(buf);
}
#endif /* DIAG_HAVE_ERRORLOG_HANDLER */

static void backtrace_child_init(apr_pool_t *p, server_rec *s)
{
    main_server = s;
}

static void backtrace_register_hooks(apr_pool_t *p)
{
#if DIAG_HAVE_ERRORLOG_HANDLER
    ap_register_errorlog_handler(p, "B", backtrace_log, 0);
#endif
    ap_hook_child_init(backtrace_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    APR_REGISTER_OPTIONAL_FN(backtrace_describe_exception);
    APR_REGISTER_OPTIONAL_FN(backtrace_get_backtrace);
}

module AP_MODULE_DECLARE_DATA backtrace_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    backtrace_register_hooks,
};
