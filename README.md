# DataptrHook
ntoskrnl .data pointer hook on NtConvertBetweenAuxiliaryCounterAndPerformanceCounter for UM-KM communication 

# Motivation (for newbies) 
the standard way to communicate between a usermode client and a kernel mode driver is through IOCTLs 

IOCTLs require the driver to create both DriverObject & DeviceObject , and the User can send I/O to the device over a  Symbolic Link 

Speaking specifically of mapped drivers , this makes it extremly trivial to detect. all we have to do is traverse all DriverObjects on the system (feaisble via ZwOpenDirectoryObject + ObReferenceObjectByHandle) and for each driver make sure the DriverObject->DriverInit member points to a module in the PsLoadedModuleList 

thus , mapped drivers evolved and started hijacking IRP_MJ_DEVICE_CONTROL dispatch routines of legitimate loaded drivers , this is also fairly trivial to detect by looking for dispatch hooks and patches 

In order to communicate with our mapped driver undetected , we need another way 

#  .data pointers 
The idea is simple , we want to find a kernel function that:
* calls another function by a .data pointer (allows us to steal the control flow without patching .text or triggering PatchGuard!) 
* can be triggered from UserMode (well , so we want to use it whenever we have a message to send to the driver from usermode ...) 
* gets at least one useful argument (so we can pass data to our driver)

# Sounds good , but  do we find a .data pointer ?
we can take advantage of control flow guard by searching for '_guard_dispatch' prefixed calls , to elaborate : 

when a module is compiled with /guard:cf , the compiler will analyze control flow for indirect call targets at compile time and insert code (ie _guard_dispatch_icall and others) to verify the targets at runtime 
so , simply put , looking for _guard_dispatch calls will lead us to indirect calls 

we can ALT+T in IDA to find all occurences of _guard_dispatch in ntoskrnl (or any other module that is somewhat exposed to usermode, like win32k.sys)

CTRL + F  for Nt prefixed functions (often being syscalls -> can be called from Usermode) 

reverse the function , specifically : 
* understand the code path that leads to the indirect call -  can we trigger it from UM ?
* understand the function prototype , can you use it for the way you communicate ?
* find the corresponding native api function and call it accordingly in your client


# PoC : NtConvertBetweenAuxiliaryCounterAndPerformanceCounter 
the function converts the specified auxiliary counter value to the corresponding performance counter value; optionally provides the estimated conversion error in nanoseconds due to latencies and maximum possible drift , but we dont care about that!
what so do care about , is the fact the function is calling nt!HalpTimerConvertAuxiliaryCounterToPerformanceCounter by a .data pointer in HalPrivateDispatchTable : ) 

In addition , we can pass a pointer (to a pointer) to a struct to it , and it wil 

