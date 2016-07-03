# CryptoMalloc
Encrypt your RAM!!! Allows you to encrypt the "physical" memory of any process.

# How does it work?
CryptoMalloc as the name suggest overloads the libc standard malloc function and replaces it with the one that will map process' virtual memory to a managed ANONYMOUS mapping. For all allocations CryptoMalloc keeps track of two virtual address one for the user/process to access and one for the cryptosystem. The virtual addresses are locked using mprotect and encrypted using Rijndael(AES)-128, accessing which from the user virtual address will cause a segmentation fault. CryptoMalloc sets up a signal handler to catch segmentation faults, and if it finds that the address that was being accessed is encrypted it will decrypt it and hand it back to the process transparently.

# Why?
* For fun!
* To avoid virtual machine introspection, if you don't trust your hypervisor/host (Public Cloud, Public Grid)
* Untrusted hardware? You never know...
* Use is as an anti-debugging mechanism?
* Protect application memory from modification

# Binary encryption
CryptoMalloc nicely integrates with binary encryption, allowing your code to remain secure, and decrypted on demand as it is needed, and encrypted back as soon as it is not needed. Hence greatly minimizing the attack surface for the application as only a few pages remain decrypted at any one time for interval that can be set by the user. This is known as running line encryption. Please look at the development branch 'text_encrypt' to find out more. This functionality will be later merged with 'master'.

# How fast is it?
Not too fast, but if your are paranoid about security, its fast enough! From the tests so far:
* Decrypted memory access is just as fast as normal RAM
* Decryption takes about 200-400 microseconds, depending on hardware.
* Malloc ~ 10 us (which is pretty fast actually)
* Others - not tested...

# Note on encryption:
Stack will not be encrypted! As stack allocations are not done through malloc, only the dynamic allocations will be encrypted. Virtual Memory is also technically encrypted meaning that even if the process was core dumped the information will still be safe. Encryption currently occurs in periodical basis, the parameters will be adjustable. Because processors cannot operate on encrypted memory the working set has to be in clear-text. So information will still be leaked, but hopefully much harder to capture.

# How to use it?
If you have the source code for the software whose ram you want encrypted, simply link the CryptoMalloc like any other standard shared library and compile your code, and it should work as is. If you don't however you can use the following tricks to load it into your binary runtime:

```bash
# Mac OS X, It is not developed for OSX, but in theory it should work on any POSIX (may need minor modifications)
DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=libCryptoMalloc.dylib [application]
# Linux, Totally works :)
LD_PRELOAD=cryptomalloc.so [application]
# OR
./cmalloc.sh [application]
```
CryptoMalloc also provides a shell script that will do this for you! (cmalloc.sh)

# Issues:
* Kernel doesnt trigger sigsegv on memory passed to it via syscall, so it will see the encrypted memory (fix is not very easy, requires to intercept syscalls, alternatively use crypto aware api)
* The memory management data-structure is not efficient (use rb-tree from linux kernel)
* allocator needs improvements as it currently badly suffers from fragmentation, I can use other malloc() implementation (however I'm lazy)
