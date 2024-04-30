Intended solver for Execute as a Service.
Notes:
The intended solution was using printf (format string) to leak libc. When overflowing the executeAsAService function (After changing the path), rdi contains the address of the path, the format string should be stored there.
Calling printf requires setting rax register to 0, however there are no gadgets in the binary to do so. In order to make rax null, you'll have to dump the vd.so memory area & extract gadgets from there, there's a xor eax, eax; ret; gadget. That memory area depends on the kernel used and that's the main reason for using this specific setup (qemu).
After the libc leak, you should be able to either pop a shell or open/read/write the flag (Which was I used in the solver).

Writing this with pwntools wouldn't work since some bytes are not written in memory, If someone knows the reason please let me know, I spent a while looking into it.