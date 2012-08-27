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

#ifndef MOD_BACKTRACE_H
#define MOD_BACKTRACE_H

#include "apr_optional.h"

#include "diag.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BT_OUTPUT_ERROR_LOG,
    BT_OUTPUT_FN,
    BT_OUTPUT_BUFFER,
    BT_OUTPUT_FILE
} bt_output_mode_t;

typedef enum {
    BT_OUTPUT_SHORT, /* just the function names */
    BT_OUTPUT_MEDIUM, /* function names and offsets */
    BT_OUTPUT_LONG /* everything the native feature provides, which provides
                    * simpler code
                    */
} bt_output_style_t;

typedef struct {
    bt_output_mode_t output_mode;
    bt_output_style_t output_style;
#ifdef WIN32
    HANDLE outfile;
#else
    int outfile;
#endif
    char *buffer;
    size_t buffer_size;
    void *user_data;
    void (*output_fn)(void *user_data, const char *);
    int backtrace_count;
} bt_param_t;

APR_DECLARE_OPTIONAL_FN(void, backtrace_describe_exception,
                        (diag_param_t *));
APR_DECLARE_OPTIONAL_FN(void, backtrace_get_backtrace,
                        (bt_param_t *));

#ifdef __cplusplus
}
#endif

#endif /* MOD_BACKTRACE_H */
