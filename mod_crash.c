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
#include "http_protocol.h"

#include "diagplat.h"

#if DIAG_PLATFORM_UNIX
#include <unistd.h>
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
APLOG_USE_MODULE(crash);
#endif

/* Use this LOG_PREFIX only on non-debug messages.  This provides a module
 * identifer with httpd < 2.4.
 */
#if AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
#define LOG_PREFIX ""
#else
#define LOG_PREFIX "mod_crash: "
#endif

static void crash(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                  LOG_PREFIX "about to crash");

    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "Crashing in process %" APR_PID_T_FMT "...\n", getpid());
    ap_rflush(r);
    apr_sleep(apr_time_msec(500));

    *(int *)0xdeadbeef = 0xcafebabe;
}

static int crash_handler(request_rec *r)
{
    if (!strcmp(r->handler, "crash-handler")) {
        crash(r);
        /* unreached */
    }

    return DECLINED;
}

static void crash_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(crash_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA crash_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    crash_register_hooks
};
