# CryptoMalloc
Encrypt your RAM!!! Allows you to encrypt the "physical" memory of any process.

# How does it work?
CryptoMalloc as the name suggest overloads the libc standard malloc function and replaces it with the one that will map processe's virtual memory to a file on tmpfs (essentially physical memory). For all alocations CryptoMalloc keeps track of two virtual address one for the user/process to access and one for the cryptosystem. The virtual addresses are locked using mprotect and encrypted using Rijndael(AES)-128, accessing which from the user virtual adress will cause a segmentation fault. CryptoMalloc sets up a signal handler to catch segmentation faults, and if it finds that the address that was being accessed is encrypted it will decrypt it and hand it back to the process transparently.

# Why?
* For fun!
* To avoid virtual machine introspection, if you dont trust your hypervisor/host (Public Cloud, Public Grid)
* Use FS as RAM? Because CryptoMalloc maps memory to files on your file system you could utilize your secondary storage for situations when you don't need fast memory but need a lot of it. 
* Untrusted hardware? You never know...

# How fast is it?
Not too fast, but if your are paranoid about security, its fast enough! From the tests so far:
* Decrypted memory access is just as fast as normal RAM
* Decryption takes about 200-400 microseconds, depending on hardware.
* Malloc - not tested...
* Others - not tested...

# Note on encryption:
Stack will not be encrypted! As stack allocations are not done through malloc, only the dynamic allocations will be encrypted. Virtual Memory is also technically encrypted meaning that even if the process was core dumped the information will still be safe. Encryption currently occurs in periodical basis, the parameters will be adjustable. Because processors cannot operate on encrypted memory the working set has to be in cleartext. So information will still be leaked, but hopefully much harder to capture.

# How to use it?
If you have the source code for the software whose ram you want encrypted, simply link the CryptoMalloc like any other standard shared library and compile your code, and it should work as is. If you dont however you can use the following tricks to load it into your binary runtime:

```bash
# Mac OS X, support for OSX is a bit weird, but will be better soon :)
DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=libCryptoMalloc.dylib [application]
# Linux
LD_PRELOAD=cryptomalloc.so [application]
```
CryptoMalloc also provides a shell script that will do this for you!
