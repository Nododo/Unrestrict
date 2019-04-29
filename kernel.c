#include <kernel.h>
#include <common.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <kexecute.h>

const char *abs_path_exceptions[] = {
    "/Library",
    "/private/var/mobile/Library",
    "/System/Library/Caches",
    "/private/var/mnt",
    NULL
};

task_t task_for_pid_zero = TASK_NULL;
uint64_t kernel_base = 0;
uint64_t kernel_slide = 0;
uint64_t offset_cache = 0;

#define MAX_CHUNK_SIZE 0xFFF

size_t kread(uint64_t where, void *p, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz = 0;
        mach_vm_size_t chunk = MAX_CHUNK_SIZE;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        kern_return_t kr = mach_vm_read_overwrite(task_for_pid_zero, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (kr != KERN_SUCCESS || sz == 0) {
            LOG("Unable to read kernel memory @%p: %s", (void*)(offset + where), mach_error_string(kr));
            break;
        }
        offset += sz;
    }
    return offset;
}

size_t kwrite(uint64_t where, const void *p, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = MAX_CHUNK_SIZE;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        kern_return_t kr = mach_vm_write(task_for_pid_zero, where + offset, (mach_vm_offset_t)p + offset, chunk);
        if (kr != KERN_SUCCESS) {
            LOG("Unable to write to kernel memory @%p: %s", (void*)(offset + where), mach_error_string(kr));
            break;
        }
        offset += chunk;
    }
    return offset;
}

uint64_t kalloc(vm_size_t size) {
    mach_vm_address_t address = 0;
    kern_return_t kr = mach_vm_allocate(task_for_pid_zero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        LOG("Unable to allocate kernel memory: %s", mach_error_string(kr));
        return 0;
    }
    return address;
}

bool kfree(mach_vm_address_t address, vm_size_t size) {
    kern_return_t kr = mach_vm_deallocate(task_for_pid_zero, address, size);
    if (kr != KERN_SUCCESS) {
        LOG("Unable to deallocate kernel memory: %s", mach_error_string(kr));
        return false;
    }
    return true;
}

void kwrite64(uint64_t where, uint64_t what) {
    kwrite(where, &what, sizeof(what));
}

void kwrite32(uint64_t where, uint32_t what) {
    kwrite(where, &what, sizeof(what));
}

uint64_t kread64(uint64_t where) {
    uint64_t val = 0;
    kread(where, &val, sizeof(where));
    return val;
}

uint32_t kread32(uint64_t where) {
    uint64_t val = 0;
    kread(where, &val, sizeof(where));
    return val;
}

uint64_t find_proc_struct_in_kernel_memory(pid_t pid) {
    uint64_t proc = GETOFFSET(kernel_task);
    proc = kread64(proc);
    proc = kread64(proc + offsetof_task_bsd_info);
    while (proc != 0) {
        if (kread32(proc + offsetof_proc_p_pid) == pid) {
            break;
        }
        proc = kread64(proc + offsetof_proc_p_list);
    }
    return proc;
}

uint64_t find_port(mach_port_name_t port) {
    uint64_t port_addr = 0;
    static uint64_t is_table = 0;
    if (is_table == 0) {
        is_table = find_proc_struct_in_kernel_memory(getpid());
        is_table = kread64(is_table + offsetof_proc_task);
        is_table = kread64(is_table + offsetof_task_itk_space);
        is_table = kread64(is_table + offsetof_ipc_space_is_table);
    }
    port_addr = kread64(is_table + (MACH_PORT_INDEX(port) * SIZEOF_STRUCT_IPC_ENTRY));
    return port_addr;
}

uint64_t task_self_addr() {
    static uint64_t task_self = 0;
    if (task_self == 0) {
        task_self = find_port(mach_task_self());
    }
    return task_self;
}

void set_platform_binary(uint64_t proc, bool set)
{
    uint64_t task = kread64(proc + offsetof_proc_task);
    if (task != 0) {
        uint32_t task_t_flags = kread32(task + offsetof_task_t_flags);
        if (set) {
            task_t_flags |= TF_PLATFORM;
        } else {
            task_t_flags &= ~(TF_PLATFORM);
        }
        kwrite32(task + offsetof_task_t_flags, task_t_flags);
    }
}

// Thanks to @Siguza

uint64_t zm_fix_addr(uint64_t addr) {
    typedef struct {
        uint64_t prev;
        uint64_t next;
        uint64_t start;
        uint64_t end;
    } kmap_hdr_t;
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    if (zm_hdr.start == 0) {
        uint64_t zone_map = kread64(GETOFFSET(zone_map_ref));
        LOG("zone_map: %llx ", zone_map);
        // hdr is at offset 0x10, mutexes at start
        size_t r = kread(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        LOG("zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            LOG("kread of zone_map failed!");
            return 0;
        }
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            LOG("zone_map is too big, sorry.");
            return 0;
        }
    }
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}

void set_csflags(uint64_t proc, uint32_t flags, bool value) {
    uint32_t csflags = kread32(proc + offsetof_proc_p_csflags);
    if (value == true) {
        csflags |= flags;
    } else {
        csflags &= ~flags;
    }
    kwrite32(proc + offsetof_proc_p_csflags, csflags);
}

size_t kstrlen(uint64_t ptr) {
    size_t kstrlen = (size_t)kexecute(GETOFFSET(strlen), ptr, 0, 0, 0, 0, 0, 0);
    return kstrlen;
}

uint64_t kstralloc(const char *str) {
    size_t str_kptr_size = strlen(str) + 1;
    uint64_t str_kptr = kalloc(str_kptr_size);
    if (str_kptr != 0) {
        kwrite(str_kptr, str, str_kptr_size);
    }
    return str_kptr;
}

void kstrfree(uint64_t ptr) {
    if (ptr != 0) {
        size_t size = kstrlen(ptr);
        kfree(ptr, size);
    }
}

uint64_t sstrdup(const char *str) {
    uint64_t sstrdup = 0;
    uint64_t kstr = kstralloc(str);
    if (kstr != 0) {
        sstrdup = kexecute(GETOFFSET(sstrdup), kstr, 0, 0, 0, 0, 0, 0);
        sstrdup = zm_fix_addr(sstrdup);
        kstrfree(kstr);
    }
    return sstrdup;
}

uint64_t smalloc(size_t size) {
    uint64_t smalloc = kexecute(GETOFFSET(smalloc), (uint64_t)size, 0, 0, 0, 0, 0, 0);
    smalloc = zm_fix_addr(smalloc);
    return smalloc;
}

int extension_create_file(uint64_t saveto, uint64_t sb, const char *path, size_t path_len, uint32_t subtype) {
    int extension_create_file = -1;
    uint64_t kstr = kstralloc(path);
    if (kstr != 0) {
        extension_create_file = (int)kexecute(GETOFFSET(extension_create_file), saveto, sb, kstr, (uint64_t)path_len, (uint64_t)subtype, 0, 0);
        kstrfree(kstr);
    }
    return extension_create_file;
}

int extension_add(uint64_t ext, uint64_t sb, const char *desc) {
    int extension_add = -1;
    uint64_t kstr = kstralloc(desc);
    if (kstr != 0) {
        extension_add = (int)kexecute(GETOFFSET(extension_add), ext, sb, kstr, 0, 0, 0, 0);
        kstrfree(kstr);
    }
    return extension_add;
}

void extension_release(uint64_t ext) {
    kexecute(GETOFFSET(extension_release), ext, 0, 0, 0, 0, 0, 0);
}

bool set_file_extension(uint64_t sandbox, const char *exc_key, const char *path) {
    bool set_file_extension = false;
    if (sandbox != 0) {
        uint64_t ext = smalloc(SIZEOF_STRUCT_EXTENSION);
        if (ext != 0) {
            int ret_extension_create_file = extension_create_file(ext, sandbox, path, strlen(path) + 1, 0);
            if (ret_extension_create_file == 0) {
                int ret_extension_add = extension_add(ext, sandbox, exc_key);
                if (ret_extension_add == 0) {
                    set_file_extension = true;
                }
            }
            extension_release(ext);
        }
    } else {
        set_file_extension = true;
    }
    return set_file_extension;
}

uint64_t proc_find(pid_t pid) {
    uint64_t proc_find = kexecute(GETOFFSET(proc_find), (uint64_t)pid, 0, 0, 0, 0, 0, 0);
    if (proc_find != 0) {
        proc_find = zm_fix_addr(proc_find);
    }
    return proc_find;
}

void proc_rele(uint64_t proc) {
    kexecute(GETOFFSET(proc_rele), proc, 0, 0, 0, 0, 0, 0);
}

bool OSDictionary_SetItem(uint64_t OSDictionary, const char *key, uint64_t val) {
    bool OSDictionary_SetItem = false;
    uint64_t function = OSObjectFunc(OSDictionary, off_OSDictionary_SetObjectWithCharP);
    if (function != 0) {
        uint64_t kstr = kstralloc(key);
        if (kstr != 0) {
            OSDictionary_SetItem = (bool)kexecute(function, OSDictionary, kstr, val, 0, 0, 0, 0);
            kstrfree(kstr);
        }
    }
    return OSDictionary_SetItem;
}

uint64_t OSDictionary_GetItem(uint64_t OSDictionary, const char *key) {
    uint64_t OSDictionary_GetItem = false;
    uint64_t function = OSObjectFunc(OSDictionary, off_OSDictionary_GetObjectWithCharP);
    if (function != 0) {
        uint64_t kstr = kstralloc(key);
        if (kstr != 0) {
            OSDictionary_GetItem = kexecute(function, OSDictionary, kstr, 0, 0, 0, 0, 0);
            if (OSDictionary_GetItem != 0 && (OSDictionary_GetItem >> 32) == 0) {
                OSDictionary_GetItem = zm_fix_addr(OSDictionary_GetItem);
            }
            kstrfree(kstr);
        }
    }
    return OSDictionary_GetItem;
}

bool OSDictionary_Merge(uint64_t OSDictionary, uint64_t OSDictionary2) {
    bool OSDictionary_Merge = false;
    uint64_t function = OSObjectFunc(OSDictionary, off_OSDictionary_Merge);
    if (function != 0) {
        OSDictionary_Merge = (bool)kexecute(function, OSDictionary, OSDictionary2, 0, 0, 0, 0, 0);
    }
    return OSDictionary_Merge;
}

uint32_t OSDictionary_ItemCount(uint64_t OSDictionary) {
    uint32_t OSDictionary_ItemCount = 0;
    if (OSDictionary != 0) {
        OSDictionary_ItemCount = kread32(OSDictionary + 20);
    }
    return OSDictionary_ItemCount;
}

uint64_t OSDictionary_ItemBuffer(uint64_t OSDictionary) {
    uint64_t OSDictionary_ItemBuffer = 0;
    if (OSDictionary != 0) {
        OSDictionary_ItemBuffer = kread64(OSDictionary + 32);
    }
    return OSDictionary_ItemBuffer;
}

uint64_t OSDictionary_ItemKey(uint64_t buffer, uint32_t idx) {
    uint64_t OSDictionary_ItemKey = 0;
    if (buffer != 0) {
        OSDictionary_ItemKey = kread64(buffer + 16 + idx);
    }
    return OSDictionary_ItemKey;
}

uint64_t OSDictionary_ItemValue(uint64_t buffer, uint32_t idx) {
    uint64_t OSDictionary_ItemValue = 0;
    if (buffer != 0) {
        OSDictionary_ItemValue = kread64(buffer + 16 * idx + 8);
    }
    return OSDictionary_ItemValue;
}

bool OSArray_Merge(uint64_t OSArray, uint64_t OSArray2) {
    bool OSArray_Merge = false;
    uint64_t function = OSObjectFunc(OSArray, off_OSArray_Merge);
    if (function != 0) {
        OSArray_Merge = (bool)kexecute(function, OSArray, OSArray2, 0, 0, 0, 0, 0);
    }
    return OSArray_Merge;
}

uint64_t OSArray_GetObject(uint64_t OSArray, uint32_t idx) {
    uint64_t OSArray_GetObject = 0;
    uint64_t function = OSObjectFunc(OSArray, off_OSArray_GetObject);
    if (function != 0) {
        OSArray_GetObject = kexecute(OSArray, idx, 0, 0, 0, 0, 0, 0);
        if (OSArray_GetObject != 0) {
            OSArray_GetObject = zm_fix_addr(OSArray_GetObject);
        }
    }
    return OSArray_GetObject;
}

void OSArray_RemoveObject(uint64_t OSArray, uint32_t idx) {
    uint64_t function = OSObjectFunc(OSArray, off_OSArray_RemoveObject);
    if (function != 0) {
        kexecute(function, OSArray, idx, 0, 0, 0, 0, 0);
    }
}

uint32_t OSArray_ItemCount(uint64_t OSArray) {
    uint32_t OSArray_ItemCount = 0;
    if (OSArray != 0) {
        OSArray_ItemCount = kread32(OSArray + 0x14);
    }
    return OSArray_ItemCount;
}

uint64_t OSArray_ItemBuffer(uint64_t OSArray) {
    uint64_t OSArray_ItemBuffer = 0;
    if (OSArray != 0) {
        OSArray_ItemBuffer = kread64(OSArray + 32);
    }
    return OSArray_ItemBuffer;
}

uint64_t OSObjectFunc(uint64_t OSObject, uint32_t off) {
    uint64_t OSObjectFunc = 0;
    uint64_t vtable = kread64(OSObject);
    vtable = kernel_xpacd(vtable);
    if (vtable != 0) {
        OSObjectFunc = kread64(vtable + off);
        OSObjectFunc = kernel_xpaci(OSObjectFunc);
    }
    return OSObjectFunc;
}

void OSObject_Release(uint64_t OSObject) {
    uint64_t function = OSObjectFunc(OSObject, off_OSObject_Release);
    if (function != 0) {
        kexecute(function, OSObject, 0, 0, 0, 0, 0, 0);
    }
}

void OSObject_Retain(uint64_t OSObject) {
    uint64_t function = OSObjectFunc(OSObject, off_OSObject_Retain);
    if (function != 0) {
        kexecute(function, OSObject, 0, 0, 0, 0, 0, 0);
    }
}

uint32_t OSObject_GetRetainCount(uint64_t OSObject) {
    uint32_t OSObject_GetRetainCount = 0;
    uint64_t function = OSObjectFunc(OSObject, off_OSObject_GetRetainCount);
    if (function != 0) {
        OSObject_GetRetainCount = (uint32_t)kexecute(function, OSObject, 0, 0, 0, 0, 0, 0);
    }
    return OSObject_GetRetainCount;
}

uint32_t OSString_GetLength(uint64_t OSString) {
    uint32_t OSString_GetLength = 0;
    uint64_t function = OSObjectFunc(OSString, off_OSString_GetLength);
    if (function != 0) {
        OSString_GetLength = (uint32_t)kexecute(function, OSString, 0, 0, 0, 0, 0, 0);
    }
    return OSString_GetLength;
}

uint64_t OSString_CStringPtr(uint64_t OSString) {
    uint64_t OSString_CStringPtr = 0;
    if (OSString != 0) {
        OSString_CStringPtr = kread64(OSString + 0x10);
    }
    return OSString_CStringPtr;
}

char *OSString_CopyString(uint64_t OSString) {
    char *OSString_CopyString = NULL;
    uint32_t length = OSString_GetLength(OSString);
    if (length != 0) {
        char *str = malloc(length + 1);
        if (str != NULL) {
            str[length] = 0;
            uint64_t CStringPtr = OSString_CStringPtr(OSString);
            if (CStringPtr != 0) {
                if (kread(CStringPtr, str, length) == length) {
                    OSString_CopyString = strdup(str);
                }
            }
            SafeFreeNULL(str);
        }
    }
    return OSString_CopyString;
}

uint64_t OSUnserializeXML(const char *buffer) {
    uint64_t OSUnserializeXML = 0;
    uint64_t kstr = kstralloc(buffer);
    if (kstr != 0) {
        uint64_t error_kptr = 0;
        OSUnserializeXML = kexecute(GETOFFSET(osunserializexml), kstr, error_kptr, 0, 0, 0, 0, 0);
        if (OSUnserializeXML != 0) {
            OSUnserializeXML = zm_fix_addr(OSUnserializeXML);
        }
        kstrfree(kstr);
    }
    return OSUnserializeXML;
}

uint64_t get_exception_osarray(const char **exceptions) {
    uint64_t exception_osarray = 0;
    size_t xmlsize = 0x1000;
    size_t len=0;
    ssize_t written=0;
    char *ents = malloc(xmlsize);
    if (!ents) {
        return 0;
    }
    size_t xmlused = sprintf(ents, "<array>");
    for (const char **exception = exceptions; *exception; exception++) {
        len = strlen(*exception);
        len += strlen("<string></string>");
        while (xmlused + len >= xmlsize) {
            xmlsize += 0x1000;
            ents = reallocf(ents, xmlsize);
            if (!ents) {
                return 0;
            }
        }
        written = sprintf(ents + xmlused, "<string>%s/</string>", *exception);
        if (written < 0) {
            SafeFreeNULL(ents);
            return 0;
        }
        xmlused += written;
    }
    len = strlen("</array>");
    if (xmlused + len >= xmlsize) {
        xmlsize += len;
        ents = reallocf(ents, xmlsize);
        if (!ents) {
            return 0;
        }
    }
    written = sprintf(ents + xmlused, "</array>");
    
    exception_osarray = OSUnserializeXML(ents);
    SafeFreeNULL(ents);
    return exception_osarray;
}

char **copy_amfi_entitlements(uint64_t present) {
    unsigned int itemCount = OSArray_ItemCount(present);
    uint64_t itemBuffer = OSArray_ItemBuffer(present);
    size_t bufferSize = 0x1000;
    size_t bufferUsed = 0;
    size_t arraySize = (itemCount + 1) * sizeof(char *);
    char **entitlements = malloc(arraySize + bufferSize);
    if (!entitlements) {
        return NULL;
    }
    entitlements[itemCount] = NULL;
    
    for (int i = 0; i < itemCount; i++) {
        uint64_t item = kread64(itemBuffer + (i * sizeof(void *)));
        char *entitlementString = OSString_CopyString(item);
        if (!entitlementString) {
            SafeFreeNULL(entitlements);
            return NULL;
        }
        size_t len = strlen(entitlementString) + 1;
        while (bufferUsed + len > bufferSize) {
            bufferSize += 0x1000;
            entitlements = realloc(entitlements, arraySize + bufferSize);
            if (!entitlements) {
                SafeFreeNULL(entitlementString);
                return NULL;
            }
        }
        entitlements[i] = (char*)entitlements + arraySize + bufferUsed;
        strcpy(entitlements[i], entitlementString);
        bufferUsed += len;
        SafeFreeNULL(entitlementString);
    }
    return entitlements;
}

uint64_t getOSBool(bool value) {
    uint64_t OSBool = 0;
    if (value) {
        OSBool = kread64(GETOFFSET(OSBoolean_True));
    } else {
        OSBool = kread64(GETOFFSET(OSBoolean_True)) + sizeof(void *);
    }
    return OSBool;
}

bool entitleProcess(uint64_t amfi_entitlements, const char *key, uint64_t val) {
    bool entitleProcess = false;
    if (amfi_entitlements != 0) {
        if (OSDictionary_GetItem(amfi_entitlements, key) != val) {
            entitleProcess = OSDictionary_SetItem(amfi_entitlements, key, val);
        } else {
            entitleProcess = true;
        }
    }
    return entitleProcess;
}

bool exceptionalizeProcess(uint64_t sandbox, uint64_t amfi_entitlements, const char **exceptions) {
    bool exceptionalizeProcess = true;
    if (sandbox != 0) {
        for (const char **exception = exceptions; *exception; exception++) {
            if (!set_file_extension(sandbox, FILE_EXC_KEY, *exception)) {
                exceptionalizeProcess = false;
            }
        }
        if (amfi_entitlements != 0) {
            uint64_t presentExceptionOSArray = OSDictionary_GetItem(amfi_entitlements, FILE_EXC_KEY);
            if (presentExceptionOSArray != 0) {
                char **currentExceptions = copy_amfi_entitlements(presentExceptionOSArray);
                if (currentExceptions != NULL) {
                    for (const char **exception = exceptions; *exception; exception++) {
                        bool foundException = false;
                        for (char **entitlementString = currentExceptions; *entitlementString && !foundException; entitlementString++) {
                            char *ent = strdup(*entitlementString);
                            if (ent != NULL) {
                                size_t lastchar = strlen(ent) - 1;
                                if (ent[lastchar] == '/') ent[lastchar] = '\0';
                                if (strcasecmp(ent, *exception) == 0) {
                                    foundException = true;
                                }
                                SafeFreeNULL(ent);
                            }
                        }
                        if (!foundException) {
                            const char **exception_array = malloc(((1 + 1) * sizeof(char *)) + MAXPATHLEN);
                            if (exception_array != NULL) {
                                exception_array[0] = *exception;
                                exception_array[1] = NULL;
                                uint64_t exceptionOSArray = get_exception_osarray(exception_array);
                                if (exceptionOSArray != 0) {
                                    if (!OSArray_Merge(presentExceptionOSArray, exceptionOSArray)) {
                                        exceptionalizeProcess = false;
                                    }
                                    OSObject_Release(exceptionOSArray);
                                }
                                SafeFreeNULL(exception_array);
                            }
                        }
                    }
                    SafeFreeNULL(currentExceptions);
                }
            } else {
                uint64_t exceptionOSArray = get_exception_osarray(exceptions);
                if (exceptionOSArray != 0) {
                    if (!OSDictionary_SetItem(amfi_entitlements, FILE_EXC_KEY, exceptionOSArray)) {
                        exceptionalizeProcess = false;
                    }
                    OSObject_Release(exceptionOSArray);
                }
            }
        }
    }
    return exceptionalizeProcess;
}

bool unrestrictProcess(pid_t pid) {
    bool unrestrictProcess = true;
    LOG("%s(%d): Unrestricting", __FUNCTION__, pid);
    uint64_t proc = proc_find(pid);
    if (proc != 0) {
        LOG("%s(%d): Found proc: 0x%llx", __FUNCTION__, pid, proc);
        uint64_t proc_ucred = kread64(proc + offsetof_proc_p_ucred);
        LOG("%s(%d): Found proc_ucred: 0x%llx", __FUNCTION__, pid, proc_ucred);
        if (proc_ucred != 0) {
            char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
            bzero(pathbuf, sizeof(pathbuf));
            if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
                LOG("%s(%d): Found path: %s", __FUNCTION__, pid, pathbuf);
                struct stat statbuf;
                if (lstat(pathbuf, &statbuf) != -1) {
                    LOG("%s(%d): Got stat for path", __FUNCTION__, pid);
                    if (statbuf.st_mode & S_ISUID) {
                        LOG("%s(%d): Enabling setuid", __FUNCTION__, pid);
                        kwrite32(proc + offsetof_proc_svuid, statbuf.st_uid);
                        kwrite32(proc_ucred + offsetof_ucred_cr_svuid, statbuf.st_uid);
                        kwrite32(proc_ucred + offsetof_ucred_cr_uid, statbuf.st_uid);
                    }
                    if (statbuf.st_mode & S_ISGID) {
                        LOG("%s(%d): Enabling setgid", __FUNCTION__, pid);
                        kwrite32(proc + offsetof_proc_svgid, statbuf.st_gid);
                        kwrite32(proc_ucred + offsetof_ucred_cr_svgid, statbuf.st_gid);
                        kwrite32(proc_ucred + offsetof_ucred_cr_groups, statbuf.st_gid);
                    }
                } else {
                    LOG("%s(%d): Unable to get stat for path", __FUNCTION__, pid);
                    unrestrictProcess = false;
                }
            } else {
                LOG("%s(%d): Unable to find path", __FUNCTION__, pid);
                unrestrictProcess = false;
            }
            uint64_t cr_label = kread64(proc_ucred + offsetof_ucred_cr_label);
            if (cr_label != 0) {
                LOG("%s(%d): Found cr_label: 0x%llx", __FUNCTION__, pid, cr_label);
                uint64_t amfi_entitlements = get_amfi_entitlements(cr_label);
                uint64_t sandbox = get_sandbox(cr_label);
                LOG("%s(%d): Entitling process with: %s", __FUNCTION__, pid, "com.apple.private.skip-library-validation");
                entitleProcess(amfi_entitlements, "com.apple.private.skip-library-validation", OSBoolTrue);
                if (OPT(GET_TASK_ALLOW)) {
                    LOG("%s(%d): Entitling process with: %s", __FUNCTION__, pid, "get-task-allow");
                    entitleProcess(amfi_entitlements, "get-task-allow", OSBoolTrue);
                }
                if (strcmp(pathbuf, "/usr/libexec/securityd") != 0) {
                    LOG("%s(%d): Exceptionalizing process with: %s", __FUNCTION__, pid, "abs_path_exceptions");
                    if (!exceptionalizeProcess(sandbox, amfi_entitlements, abs_path_exceptions)) {
                        LOG("%s(%d): Unable to exceptionalize process", __FUNCTION__, pid);
                        unrestrictProcess = false;
                    }
                }
                if (amfi_entitlements != 0) {
                    if (OSDictionary_GetItem(amfi_entitlements, "platform-application") == OSBoolTrue) {
                        LOG("%s(%d): Setting TF_PLATFORM", __FUNCTION__, pid);
                        set_platform_binary(proc, true);
                    }
                }
            } else {
                LOG("%s(%d): Unable to find cr_label", __FUNCTION__, pid);
                unrestrictProcess = false;
            }
        } else {
            LOG("%s(%d): Unable to find proc_ucred", __FUNCTION__, pid);
            unrestrictProcess = false;
        }
        uint32_t cs_flags = 0;
        if (csops(pid, CS_OPS_STATUS, (void *)&cs_flags, sizeof(cs_flags)) == 0) {
            LOG("%s(%d): Found cs_flags: 0x%x", __FUNCTION__, pid, cs_flags);
            if (!(cs_flags & CS_PLATFORM_BINARY)) {
                LOG("%s(%d): Setting CS_PLATFORM_BINARY", __FUNCTION__, pid);
                set_csflags(proc, CS_PLATFORM_BINARY, true);
            }
            if ((cs_flags & CS_REQUIRE_LV)) {
                LOG("%s(%d): Unsetting CS_REQUIRE_LV", __FUNCTION__, pid);
                set_csflags(proc, CS_REQUIRE_LV, false);
            }
            if ((cs_flags & CS_CHECK_EXPIRATION)) {
                LOG("%s(%d): Unsetting CS_CHECK_EXPIRATION", __FUNCTION__, pid);
                set_csflags(proc, CS_CHECK_EXPIRATION, false);
            }
            if (!(cs_flags & CS_DYLD_PLATFORM)) {
                LOG("%s(%d): Setting CS_DYLD_PLATFORM", __FUNCTION__, pid);
                set_csflags(proc, CS_DYLD_PLATFORM, true);
            }
            if (OPT(GET_TASK_ALLOW)) {
                if (!(cs_flags & CS_GET_TASK_ALLOW)) {
                    LOG("%s(%d): Setting CS_GET_TASK_ALLOW", __FUNCTION__, pid);
                    set_csflags(proc, CS_GET_TASK_ALLOW, true);
                }
                if (!(cs_flags & CS_INSTALLER)) {
                    LOG("%s(%d): Setting CS_INSTALLER", __FUNCTION__, pid);
                    set_csflags(proc, CS_INSTALLER, true);
                }
                if ((cs_flags & CS_RESTRICT)) {
                    LOG("%s(%d): Unsetting CS_RESTRICT", __FUNCTION__, pid);
                    set_csflags(proc, CS_RESTRICT, false);
                }
            }
            if (OPT(CS_DEBUGGED)) {
                if (!(cs_flags & CS_DEBUGGED)) {
                    LOG("%s(%d): Setting CS_DEBUGGED", __FUNCTION__, pid);
                    set_csflags(proc, CS_DEBUGGED, true);
                }
                if ((cs_flags & CS_HARD)) {
                    LOG("%s(%d): Unsetting CS_HARD", __FUNCTION__, pid);
                    set_csflags(proc, CS_HARD, false);
                }
                if ((cs_flags & CS_KILL)) {
                    LOG("%s(%d): Unsetting CS_KILL", __FUNCTION__, pid);
                    set_csflags(proc, CS_KILL, false);
                }
            }
        } else {
            LOG("%s(%d): Unable to find cs_flags", __FUNCTION__, pid);
            unrestrictProcess = false;
        }
        LOG("%s(%d): Releasing proc", __FUNCTION__, pid);
        proc_rele(proc);
    } else {
        LOG("%s(%d): Unable to find proc", __FUNCTION__, pid);
        unrestrictProcess = false;
    }
    if (unrestrictProcess) {
        LOG("%s(%d): Unrestricted process", __FUNCTION__, pid);
    } else {
        LOG("%s(%d): Unable to unrestrict process", __FUNCTION__, pid);
    }
    return unrestrictProcess;
}

bool unrestrictProcessWithTaskPort(mach_port_t task_port) {
    bool unrestrictProcessWithTaskPort = false;
    pid_t pid = 0;
    if (pid_for_task(mach_task_self(), &pid) == KERN_SUCCESS) {
        unrestrictProcessWithTaskPort = unrestrictProcess(pid);
    }
    return unrestrictProcessWithTaskPort;
}

bool revalidateProcess(pid_t pid) {
    bool revalidateProcess = true;
    LOG("%s(%d): Revalidating", __FUNCTION__, pid);
    uint32_t cs_flags = 0;
    if (csops(pid, CS_OPS_STATUS, (void *)&cs_flags, sizeof(cs_flags)) == 0) {
        if (!(cs_flags & CS_VALID)) {
            uint64_t proc = proc_find(pid);
            if (proc != 0) {
                LOG("%s(%d): Found proc: 0x%llx", __FUNCTION__, pid, proc);
                LOG("%s(%d): Setting CS_VALID", __FUNCTION__, pid);
                set_csflags(proc, CS_VALID, true);
                LOG("%s(%d): Releasing proc", __FUNCTION__, pid);
                proc_rele(proc);
            } else {
                LOG("%s(%d): Unable to find proc", __FUNCTION__, pid);
                revalidateProcess = false;
            }
        }
    }
    if (revalidateProcess) {
        LOG("%s(%d): Revalidated process", __FUNCTION__, pid);
    } else {
        LOG("%s(%d): Unable to revalidate process", __FUNCTION__, pid);
    }
    return revalidateProcess;
}

bool revalidateProcessWithTaskPort(mach_port_t task_port) {
    bool revalidateProcessWithTaskPort = false;
    pid_t pid = 0;
    if (pid_for_task(mach_task_self(), &pid) == KERN_SUCCESS) {
        revalidateProcessWithTaskPort = revalidateProcess(pid);
    }
    return revalidateProcessWithTaskPort;
}

uint64_t get_amfi_entitlements(uint64_t cr_label) {
    uint64_t amfi_entitlements = 0;
    amfi_entitlements = kread64(cr_label + 0x8);
    return amfi_entitlements;
}

uint64_t get_sandbox(uint64_t cr_label) {
    uint64_t sandbox = 0;
    sandbox = kread64(cr_label + 0x8 + 0x8);
    return sandbox;
}

bool entitleProcessWithPid(pid_t pid, const char *key, uint64_t val) {
    bool entitleProcessWithPid = true;
    uint64_t proc = proc_find(pid);
    if (proc != 0) {
        LOG("%s: Found proc: 0x%llx", __FUNCTION__, proc);
        uint64_t proc_ucred = kread64(proc + offsetof_proc_p_ucred);
        if (proc_ucred != 0) {
            LOG("%s: Found proc_ucred: 0x%llx", __FUNCTION__, proc_ucred);
            uint64_t cr_label = kread64(proc_ucred + offsetof_ucred_cr_label);
            if (cr_label != 0) {
                LOG("%s: Found cr_label: 0x%llx", __FUNCTION__, cr_label);
                uint64_t amfi_entitlements = get_amfi_entitlements(cr_label);
                if (amfi_entitlements != 0) {
                    LOG("%s: Found amfi_entitlements: 0x%llx", __FUNCTION__, amfi_entitlements);
                    entitleProcessWithPid = entitleProcess(amfi_entitlements, key, val);
                } else {
                    LOG("%s: Unable to find amfi_entitlements", __FUNCTION__);
                    entitleProcessWithPid = false;
                }
            } else {
                LOG("%s: Unable to find cr_label", __FUNCTION__);
                entitleProcessWithPid = false;
            }
        } else {
            LOG("%s: Unable to find proc_ucred", __FUNCTION__);
            entitleProcessWithPid = false;
        }
        LOG("%s: Releasing proc: 0x%llx", __FUNCTION__, proc);
        proc_rele(proc);
    } else {
        LOG("%s: Unable to find proc", __FUNCTION__);
        entitleProcessWithPid = false;
    }
    return entitleProcessWithPid;
}

bool removeMemoryLimit() {
    bool removeMemoryLimit = false;
    if (entitleProcessWithPid(getpid(), "com.apple.private.memorystatus", OSBoolTrue)) {
        if (memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid(), 0, NULL, 0) == 0) {
            removeMemoryLimit = true;
        }
    }
    return removeMemoryLimit;
}

bool haveOffsets() {
    bool haveOffsets = true;    
    haveOffsets &= (KERN_POINTER_VALID(GETOFFSET(unrestrict-options)) && KERN_POINTER_VALID(GETOFFSET(OSBoolean_True)) && KERN_POINTER_VALID(GETOFFSET(osunserializexml)) && KERN_POINTER_VALID(GETOFFSET(smalloc)) && KERN_POINTER_VALID(GETOFFSET(zone_map_ref)) && KERN_POINTER_VALID(GETOFFSET(kernel_task)) && KERN_POINTER_VALID(GETOFFSET(proc_find)) && KERN_POINTER_VALID(GETOFFSET(proc_rele)) && KERN_POINTER_VALID(GETOFFSET(extension_create_file)) && KERN_POINTER_VALID(GETOFFSET(extension_add)) && KERN_POINTER_VALID(GETOFFSET(extension_release)) && KERN_POINTER_VALID(GETOFFSET(sstrdup)) && KERN_POINTER_VALID(GETOFFSET(strlen)));
#if __arm64e__
    haveOffsets &= (KERN_POINTER_VALID(GETOFFSET(paciza_pointer__l2tp_domain_module_start)) && KERN_POINTER_VALID(GETOFFSET(paciza_pointer__l2tp_domain_module_stop)) && KERN_POINTER_VALID(GETOFFSET(l2tp_domain_inited)) && KERN_POINTER_VALID(GETOFFSET(sysctl__net_ppp_l2tp)) && KERN_POINTER_VALID(GETOFFSET(sysctl_unregister_oid)) && KERN_POINTER_VALID(GETOFFSET(mov_x0_x4__br_x5)) && KERN_POINTER_VALID(GETOFFSET(mov_x9_x0__br_x1)) && KERN_POINTER_VALID(GETOFFSET(mov_x10_x3__br_x6)) && KERN_POINTER_VALID(GETOFFSET(kernel_forge_pacia_gadget)) && KERN_POINTER_VALID(GETOFFSET(kernel_forge_pacda_gadget)) && KERN_POINTER_VALID(GETOFFSET(IOUserClient__vtable)) && KERN_POINTER_VALID(GETOFFSET(IORegistryEntry__getRegistryEntryID)));
#else
    haveOffsets &= (KERN_POINTER_VALID(GETOFFSET(add_x0_x0_0x40_ret)));
#endif
    return haveOffsets;
}
