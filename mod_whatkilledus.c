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
#include "http_log.h"
#include "ap_mpm.h"

#include "mod_backtrace.h"

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
APLOG_USE_MODULE(whatkilledus);
#endif

static APR_OPTIONAL_FN_TYPE(backtrace_describe_exception) *describe_exception;
static APR_OPTIONAL_FN_TYPE(backtrace_get_backtrace) *get_backtrace;

#if DIAG_PLATFORM_UNIX
static int exception_hook_enabled;
#endif

#if DIAG_PLATFORM_WINDOWS

static LONG WINAPI whatkilledus_crash_handler(EXCEPTION_POINTERS *ep)
{
    if (get_backtrace) {
        bt_param_t p = {0};
        diag_context_t c = {0};

        p.output_mode = BT_OUTPUT_ERROR_LOG;
        p.output_style = BT_OUTPUT_LONG;
        c.context = ep->ContextRecord;
        get_backtrace(&p, &c);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

#else

static int whatkilledus_fatal_exception(ap_exception_info_t *ei)
{
    if (get_backtrace) {
        bt_param_t p = {0};

        p.output_mode = BT_OUTPUT_ERROR_LOG;
        p.output_style = BT_OUTPUT_LONG;
        get_backtrace(&p, NULL);
    }
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
                  "mod_whatkilledus: about to crash");

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
                     "mod_whatkilledus: EnableExceptionHook must be set to On");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif
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
