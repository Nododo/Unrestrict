#include <unrestrict.h>
#include <common.h>
#include <kernel.h>
#include <kexecute.h>

static bool unrestrict_initialized = false;

bool unrestrict_init() {
    LOG("Initializing");
    kern_return_t kr = KERN_FAILURE;
    host_t host = mach_host_self();
    if (!MACH_PORT_VALID(host)) {
        LOG("Unable to get host");
        return false;
    }
    if ((kr = host_get_special_port(host, HOST_LOCAL_NODE, 4, &task_for_pid_zero)) != KERN_SUCCESS || !MACH_PORT_VALID(task_for_pid_zero)) {
        LOG("Unable to get special port: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), host);
        return false;
    }
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if ((kr = task_info(task_for_pid_zero, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count)) != KERN_SUCCESS) {
        LOG("Unable to get task info: %s", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), host);
        mach_port_deallocate(mach_task_self(), task_for_pid_zero);
        return false;
    }
    kernel_slide = dyld_info.all_image_info_size;
    kernel_base = STATIC_KERNEL_BASE + kernel_slide;
    offset_cache = dyld_info.all_image_info_addr;
    if (offset_cache == kernel_base) {
        LOG("Unable to get offset_cache");
        mach_port_deallocate(mach_task_self(), host);
        mach_port_deallocate(mach_task_self(), task_for_pid_zero);
        return false;
    }
    LOG("offset_cache: 0x%llx, kernel_slide: 0x%llx, kernel_base: 0x%llx", offset_cache, kernel_slide, kernel_base);
    size_t blob_size = kread64(offset_cache);
    struct cache_blob *blob = create_cache_blob(blob_size);
    if (blob == NULL) {
        LOG("Unable to create cache blob");
        mach_port_deallocate(mach_task_self(), host);
        mach_port_deallocate(mach_task_self(), task_for_pid_zero);
        return false;
    }
    if (kread(dyld_info.all_image_info_addr, blob, blob_size) == 0) {
        LOG("Unable to read offsetcache");
        mach_port_deallocate(mach_task_self(), host);
        mach_port_deallocate(mach_task_self(), task_for_pid_zero);
        return false;
    }
    import_cache_blob(blob);
    SafeFreeNULL(blob);
    if (GETOFFSET(kernel_slide) != kernel_slide || !haveOffsets()) {
        LOG("Unable to validate offset cache");
        mach_port_deallocate(mach_task_self(), host);
        mach_port_deallocate(mach_task_self(), task_for_pid_zero);
        return false;
    }
    if (!init_kexecute()) {
        LOG("Unable to initialize kexecute");
        mach_port_deallocate(mach_task_self(), host);
        mach_port_deallocate(mach_task_self(), task_for_pid_zero);
        return false;
    }
    mach_port_deallocate(mach_task_self(), host);
    unrestrict_initialized = true;
    LOG("Initialized successfully");
    return true;
}

void unrestrict_deinit() {
    LOG("Deinitializing");
    term_kexecute();
    mach_port_deallocate(mach_task_self(), task_for_pid_zero);
    unrestrict_initialized = false;
    LOG("Deinitialized");
}

#ifdef HAVE_MAIN

__attribute__((constructor))
static void ctor() {
    unrestrict_init();
    if (unrestrict_initialized) {
        if (!removeMemoryLimit()) {
            LOG("Unable to remove memory limit");
            unrestrict_initialized = false;
        }
    }
}

__attribute__((destructor))
static void dtor() {
    unrestrict_deinit();
}

bool MSunrestrict0(mach_port_t task) {
    if (unrestrict_initialized) {
        unrestrictProcessWithTaskPort(task);
    }
    return true;
}

bool MSrevalidate0(mach_port_t task) {
    if (unrestrict_initialized) {
        revalidateProcessWithTaskPort(task);
    }
    return true;
}

#endif
