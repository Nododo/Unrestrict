#ifndef common_h
#define common_h

#include <stdio.h>
#include <os/log.h>
#include <offsetcache.h>
#include <kernel.h>

#ifdef DEBUG
#define LOG(...) do { os_log(OS_LOG_DEFAULT, __VA_ARGS__); } while(false)
#else
#define LOG(...) do { } while (false)
#endif

#define SafeFree(x) do { if (x) free(x); } while(false)
#define SafeFreeNULL(x) do { SafeFree(x); (x) = NULL; } while(false)

#define offset_options GETOFFSET(unrestrict-options)
#define OPT(x) (offset_options?((kread64(offset_options) & OPT_ ##x)?true:false):false)
#define SETOPT(x) (offset_options?kwrite64(offset_options, kread64(offset_options) | OPT_ ##x):0)
#define UNSETOPT(x) (offset_options?kwrite64(offset_options, kread64(offset_options) & ~OPT_ ##x):0)
#define OPT_GET_TASK_ALLOW (1<<0)
#define OPT_CS_DEBUGGED (1<<1)

#define KERN_POINTER_VALID(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)

#endif
