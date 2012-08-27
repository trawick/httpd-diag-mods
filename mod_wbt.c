#include <stdio.h>
#include <time.h>

#if defined(_MSC_VER) && _MSC_VER >= 1400
#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE
#endif
#pragma warning(disable: 4996)
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT

/* Restrict the server to a subset of Windows XP header files by default
 */
#define _WIN32_WINNT 0x0502
#endif
#ifndef NOUSER
#define NOUSER
#endif
#ifndef NOMCX
#define NOMCX
#endif
#ifndef NOIME
#define NOIME
#endif
#include <windows.h>
/* APR needs these, but doesn't include them if windows.h has
 * already been included
 */
#define SW_HIDE 0
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include <dbghelp.h>

#if _MSC_VER
#define snprintf _snprintf
#endif

__declspec(dllimport) VOID NTAPI RtlCaptureContext(PCONTEXT ContextRecord);

APLOG_USE_MODULE(wbt);

struct exception_code_entry {
    DWORD symbol;
    const char *str;
};

#define one_ec_entry(s) {s,#s}
struct exception_code_entry ec_strs[] = {
    one_ec_entry(EXCEPTION_ACCESS_VIOLATION),
    one_ec_entry(EXCEPTION_ARRAY_BOUNDS_EXCEEDED),
    one_ec_entry(EXCEPTION_DATATYPE_MISALIGNMENT),
    one_ec_entry(EXCEPTION_ILLEGAL_INSTRUCTION),
    one_ec_entry(EXCEPTION_IN_PAGE_ERROR),
    one_ec_entry(EXCEPTION_INT_DIVIDE_BY_ZERO),
    one_ec_entry(EXCEPTION_STACK_OVERFLOW),
};

static void fmt_context(FILE *log,
                        CONTEXT *context_ptr)
{
    int cur = 0, limit = 25;
    STACKFRAME64 stackframe;
    CONTEXT context = *context_ptr;
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();
    char symbol_buffer[512] = {0};
    IMAGEHLP_SYMBOL64 *symbol = (IMAGEHLP_SYMBOL64 *)&symbol_buffer;
    DWORD64 ignored;

    memset(&stackframe, 0, sizeof stackframe);
    stackframe.AddrPC.Mode = 
        stackframe.AddrFrame.Mode =
            stackframe.AddrStack.Mode = AddrModeFlat;

    stackframe.AddrPC.Offset    = context.Eip;
    stackframe.AddrFrame.Offset = context.Ebp;
    stackframe.AddrStack.Offset = context.Esp;

    if (SymInitialize(process, 
                      "C:\\Apache22\\bin;C:\\Apache22\\modules;c:\\Symbols;c:\\windows\symbols;"
                      "c:\\windows\\symbols\\dll",
                      /* "SRV*C:\\MyLocalSymbols*http://msdl.microsoft.com/download/symbols" */
                      TRUE) != TRUE) {
        fprintf(log, "SymInitialize() failed with error %d\n",
                GetLastError());
    }

    while (StackWalk64(IMAGE_FILE_MACHINE_I386,
                       process, thread,
                       &stackframe,
                       &context,
                       NULL,                       /* ReadMemoryRoutine */
                       SymFunctionTableAccess64,   /* FunctionTableAccessRoutine */
                       SymGetModuleBase64,         /* GetModuleBaseRoutine */
                       NULL)                       /* TranslateAddress */
           == TRUE) {
        cur++;
        if (cur > limit) { /* avoid loop on corrupted chain */
            break;
        }
        symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
        symbol->MaxNameLength = sizeof(symbol_buffer) - sizeof(IMAGEHLP_SYMBOL64);
        ignored = 0;
        if (SymGetSymFromAddr64(process, stackframe.AddrPC.Offset, &ignored, symbol) != TRUE) {
            snprintf(symbol->Name, symbol->MaxNameLength, "no-symbol-%d", GetLastError());
        }
        fprintf(log, "  %s [0x%I64X]\n",
                symbol->Name,
                stackframe.AddrPC.Offset);
    }
}

static void fmt_exception_info(FILE *log,
                               EXCEPTION_POINTERS *ep)
{
    int i;
    char buf[20];
    const char *ch;
    
    ch = NULL;
    for (i = 0; i < sizeof(ec_strs) / sizeof(ec_strs[0]); i++) {
        if (ec_strs[i].symbol == ep->ExceptionRecord->ExceptionCode) {
            ch = ec_strs[i].str;
            break;
        }
    }
    if (ch == NULL) {
        snprintf(buf, sizeof buf, "%lu", ep->ExceptionRecord->ExceptionCode);
        ch = buf;
    }
    fprintf(log, "Exception code:    %s\n", ch);
    fprintf(log, "Exception address: %p\n", ep->ExceptionRecord->ExceptionAddress);

    fmt_context(log, ep->ContextRecord);

    fclose(log);
}

static LONG WINAPI wbt_crash_handler(EXCEPTION_POINTERS *ep)
{
    time_t now;
    FILE *log;

    time(&now);
    log = fopen("c:/Users/Trawick/crashlog.txt", "a");
    if (log) {
        fprintf(log, "========== mod_wbt report ===========================\n");
        fprintf(log, "%s", ctime(&now));
        fmt_exception_info(log, ep);
        fclose(log);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void backtrace(request_rec *r)
{
    time_t now;
    FILE *log;
    CONTEXT threadContext;

    time(&now);
    log = fopen("c:/Users/Trawick/backtracelog.txt", "a");
    if (log) {
        fprintf(log, "========== mod_wbt report ===========================\n");
        fprintf(log, "%s", ctime(&now));
        RtlCaptureContext(&threadContext);
        fmt_context(log, &threadContext);
        fclose(log);
    }
}

static void crash(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                  "mod_wbt: about to crash");

    *(int *)0xdeadbeef = 0xcafebabe;
}

static int wbt_handler(request_rec *r)
{
    if (!strcmp(r->handler, "wbt-crash-handler")) {
        crash(r);
        /* unreached */
    }

    if (!strcmp(r->handler, "wbt-backtrace-handler")) {
        backtrace(r);
        return OK;
    }

    return DECLINED;
}

static void wbt_child_init(apr_pool_t *p, server_rec *s)
{
    /* must back this out before this DLL is unloaded;
     * but previous exception filter might have been unloaded too
     */
    SetUnhandledExceptionFilter(wbt_crash_handler);
}

static void wbt_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(wbt_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(wbt_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA wbt_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    wbt_register_hooks,
};
