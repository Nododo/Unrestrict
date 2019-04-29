#ifndef kernel_h
#define kernel_h

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <pthread.h>
#include <offsetcache.h>
#include <iokit.h>
#include <parameters.h>
#include <kernel_memory.h>
#include <kernel_call.h>
#include <pac.h>

/* ---------- Missing headers ---------- */

#define PROC_PIDPATHINFO_MAXSIZE  (4 * MAXPATHLEN)
extern int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);
#define CS_OPS_STATUS 0
#define CS_OPS_ENTITLEMENTS_BLOB 7
extern int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
extern kern_return_t mach_vm_allocate(task_t task, mach_vm_address_t *addr, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(task_t task, mach_vm_address_t address, mach_vm_size_t size);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);

/* ---------- Convenience macros ---------- */

#define SETOFFSET(offset, val) set_offset(#offset, val)
#define GETOFFSET(offset) get_offset(#offset)
#define OSBoolTrue getOSBool(true)
#define OSBoolFalse getOSBool(false)

/* ---------- Static kernel offsets ---------- */

#define STATIC_KERNEL_BASE 0xfffffff007004000

/* ---------- Kernel structure sizes ---------- */

#define SIZEOF_STRUCT_IPC_ENTRY 0x18
#define SIZEOF_STRUCT_EXTENSION 0x60

/* ---------- Kernel structure offsets ---------- */

#define offsetof_proc_p_pid (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x60) : (0x10)) // proc_t::p_pid
#define offsetof_proc_task (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x10) : (0x18)) // proc_t::task
#define offsetof_proc_svuid (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x32) : (0x40)) // proc_t::svuid
#define offsetof_proc_svgid (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x36) : (0x44)) // proc_t::svgid
#define offsetof_proc_p_ucred (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0xf8) : (0x100)) // proc_t::p_ucred
#define offsetof_proc_p_csflags (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x290) : (0x2a8)) // proc_t::p_csflags
#define offsetof_proc_p_list (unsigned)(0x8) // proc_t::p_list
#define offsetof_task_itk_space (unsigned)((kCFCoreFoundationVersionNumber >= 1443.00) ? ((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x300) : (0x308)) : (0x300)) // task_t::itk_space
#if __arm64e__
#define offsetof_task_bsd_info (unsigned)(0x368) // task_t::bsd_info
#else
#define offsetof_task_bsd_info (unsigned)((kCFCoreFoundationVersionNumber >= 1443.00) ? ((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x358) : (0x368)) : (0x360)) // task_t::bsd_info
#endif
#define offsetof_ipc_port_ip_kobject (unsigned)(0x68) // ipc_port_t::ip_kobject
#define offsetof_ipc_space_is_table (unsigned)(0x20) // ipc_space::is_table

#define offsetof_ucred_cr_uid (unsigned)(0x18) // ucred::cr_uid
#define offsetof_ucred_cr_svuid (unsigned)(0x20) // ucred::cr_svuid
#define offsetof_ucred_cr_groups (unsigned)(0x28) // ucred::cr_groups
#define offsetof_ucred_cr_svgid (unsigned)(0x6c) // ucred::cr_svgid
#define offsetof_ucred_cr_label (unsigned)(0x78) // ucred::cr_label

#if __arm64e__
#define offsetof_task_t_flags (unsigned)(0x400) // task::t_flags
#else
#define offsetof_task_t_flags (unsigned)((kCFCoreFoundationVersionNumber >= 1535.12) ? (0x390) : (0x3a0)) // task::t_flags
#endif

#define offsetof_vnode_v_flag (unsigned)(0x54) // vnode::v_flag

/* ---------- Offsets from vtable ---------- */

#define off_OSDictionary_SetObjectWithCharP (sizeof(void*) * 0x1F)
#define off_OSDictionary_GetObjectWithCharP (sizeof(void*) * 0x26)
#define off_OSDictionary_Merge (sizeof(void*) * 0x23)
#define off_OSArray_Merge (sizeof(void*) * 0x1E)
#define off_OSArray_RemoveObject (sizeof(void*) * 0x20)
#define off_OSArray_GetObject (sizeof(void*) * 0x22)
#define off_OSObject_Release (sizeof(void*) * 0x05)
#define off_OSObject_GetRetainCount (sizeof(void*) * 0x03)
#define off_OSObject_Retain (sizeof(void*) * 0x04)
#define off_OSString_GetLength (sizeof(void*) * 0x11)

/* ---------- Kernel codesign flags ---------- */

#define CS_VALID 0x0000001 /* dynamically valid */
#define CS_GET_TASK_ALLOW 0x0000004 /* has get-task-allow entitlement */
#define CS_INSTALLER 0x0000008 /* has installer entitlement */
#define CS_HARD 0x0000100 /* don't load invalid pages */
#define CS_KILL 0x0000200 /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION 0x0000400 /* force expiration checking */
#define CS_RESTRICT 0x0000800 /* tell dyld to treat restricted */
#define CS_REQUIRE_LV 0x0002000 /* require library validation */
#define CS_KILLED 0x1000000 /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM 0x2000000 /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY 0x4000000 /* this is a platform binary */
#define CS_DEBUGGED 0x10000000 /* process is currently or has previously been debugged and allowed to run with invalid pages */

/* ---------- Kernel task flags ---------- */

#define TF_PLATFORM 0x00000400 /* task is a platform binary */

/* ---------- Security exception keys ---------- */

#define FILE_EXC_KEY "com.apple.security.exception.files.absolute-path.read-only"

/* ---------- Kernel memory tools ---------- */

extern task_t task_for_pid_zero;

size_t kread(uint64_t where, void *p, size_t size);
size_t kwrite(uint64_t where, const void *p, size_t size);
uint64_t kalloc(vm_size_t size);
bool kfree(mach_vm_address_t address, vm_size_t size);
void kwrite64(uint64_t where, uint64_t what);
void kwrite32(uint64_t where, uint32_t what);
uint64_t kread64(uint64_t where);
uint32_t kread32(uint64_t where);

/* ---------- Kernel utilities ---------- */

extern uint64_t kernel_base;
extern uint64_t kernel_slide;
extern uint64_t offset_cache;

uint64_t find_proc_struct_in_kernel_memory(pid_t pid);
uint64_t find_port(mach_port_name_t port);
uint64_t task_self_addr(void);
uint64_t zm_fix_addr(uint64_t addr);
void set_csflags(uint64_t proc, uint32_t flags, bool value);
size_t kstrlen(uint64_t ptr);
uint64_t kstralloc(const char *str);
void kstrfree(uint64_t ptr);
uint64_t sstrdup(const char *str);
uint64_t smalloc(size_t size);
int extension_create_file(uint64_t saveto, uint64_t sb, const char *path, size_t path_len, uint32_t subtype);
int extension_add(uint64_t ext, uint64_t sb, const char *desc);
void extension_release(uint64_t ext);
bool set_file_extension(uint64_t sandbox, const char *exc_key, const char *path);
uint64_t proc_find(pid_t pid);
void proc_rele(uint64_t proc);
bool OSDictionary_SetItem(uint64_t OSDictionary, const char *key, uint64_t val);
uint64_t OSDictionary_GetItem(uint64_t OSDictionary, const char *key);
bool OSDictionary_Merge(uint64_t OSDictionary, uint64_t OSDictionary2);
uint32_t OSDictionary_ItemCount(uint64_t OSDictionary);
uint64_t OSDictionary_ItemBuffer(uint64_t OSDictionary);
uint64_t OSDictionary_ItemKey(uint64_t buffer, uint32_t idx);
uint64_t OSDictionary_ItemValue(uint64_t buffer, uint32_t idx);
uint32_t OSArray_ItemCount(uint64_t OSArray);
bool OSArray_Merge(uint64_t OSArray, uint64_t OSArray2);
uint64_t OSArray_GetObject(uint64_t OSArray, uint32_t idx);
void OSArray_RemoveObject(uint64_t OSArray, uint32_t idx);
uint64_t OSArray_ItemBuffer(uint64_t OSArray);
uint64_t OSObjectFunc(uint64_t OSObject, uint32_t off);
void OSObject_Release(uint64_t OSObject);
void OSObject_Retain(uint64_t OSObject);
uint32_t OSObject_GetRetainCount(uint64_t OSObject);
uint32_t OSString_GetLength(uint64_t OSString);
uint64_t OSString_CStringPtr(uint64_t OSString);
char *OSString_CopyString(uint64_t OSString);
uint64_t OSUnserializeXML(const char *buffer);
uint64_t get_exception_osarray(const char **exceptions);
char **copy_amfi_entitlements(uint64_t present);
uint64_t getOSBool(bool value);
bool entitleProcess(uint64_t amfi_entitlements, const char *key, uint64_t val);
bool unrestrictProcess(pid_t pid);
bool unrestrictProcessWithTaskPort(mach_port_t task_port);
bool revalidateProcess(pid_t pid);
bool revalidateProcessWithTaskPort(mach_port_t task_port);
uint64_t get_amfi_entitlements(uint64_t cr_label);
uint64_t get_sandbox(uint64_t cr_label);
bool entitleProcessWithPid(pid_t pid, const char *key, uint64_t val);
bool removeMemoryLimit(void);
bool haveOffsets(void);

#endif
