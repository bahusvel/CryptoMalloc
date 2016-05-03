# CryptoMalloc
Encrypt your RAM!!! Allows you to encrypt the "physical" memory of any process.

# How does it work?
CryptoMalloc as the name suggest overloads the libc standard malloc function and replaces it with the one that will map processes virtual memory to a file on a file system. But how does it encrypt the RAM?!?! It doesn't on its own, it uses a RAM Disk (could be a normal disk as well) with Full Drive Encryption (FDE) enabled. Hence everything that is written to the RAM Disk will be encrypted and decrypted as needed. 

# Why?
* For fun!
* To avoid virtual machine introspection, if you dont trust your hypervisor/host (Public Cloud, Public Grid)
* Use FS as RAM? Because CryptoMalloc maps memory to files on your file system you could utilize your secondary storage for situations when you don't need fast memory but need a lot of it. 
* Untrusted hardware? You never know...

# How fast is it?
Dunno, I will test soon though.

# Note on encryption:
It doesn't encrypt your processes virtual memory or its stack, only memory that is allocated dynamically via malloc will be encrypted. This means that someone can still attach a debugger and access your memory without any issues if they are able to access your operating system, however from outside (from the hypervisor of a virtual machine) this cannot be done.

# How to use it?
```bash
# Mac OS X
DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=libCryptoMalloc.dylib [application]
# Linux
LD_PRELOAD=cryptomalloc.so [application]
```
