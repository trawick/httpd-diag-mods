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
#include "ap_mpm.h"

#include "mod_backtrace.h"

static APR_OPTIONAL_FN_TYPE(backtrace_describe_exception) *describe_exception;
static APR_OPTIONAL_FN_TYPE(backtrace_get_backtrace) *get_backtrace;

#ifndef WIN32
static int whatkilledus_fatal_exception(ap_exception_info_t *ei)
{
    if (get_backtrace) {
        bt_param_t p = {0};

        p.output_mode = BT_OUTPUT_ERROR_LOG;
        p.output_style = BT_OUTPUT_LONG;
        get_backtrace(&p);
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
#ifdef WIN32
#endif
}

static void whatkilledus_register_hooks(apr_pool_t *p)
{
#ifndef WIN32
    ap_hook_fatal_exception(whatkilledus_fatal_exception, NULL, NULL,
                            APR_HOOK_MIDDLE);
#endif
    ap_hook_optional_fn_retrieve(whatkilledus_optional_fn_retrieve, NULL, NULL,
                                 APR_HOOK_MIDDLE);
    ap_hook_child_init(whatkilledus_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA whatkilledus_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    whatkilledus_register_hooks
};
