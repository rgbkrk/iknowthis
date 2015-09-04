# Introduction #

By design, iknowthis attempts to damage the host system in unusual and unexpected ways. To run iknowthis safely, you should create an unprivileged user account and only run iknowthis inside a virtual machine that is isolated from any important data.

  * DO NOT mount any NFS shares that an unprivileged user can access.
  * DO NOT allow unprivileged users to access shared directories (for example, using vmware's hgfs system).
  * DO create an unprivileged login specifically for testing with minimal rights.

You should also enable console logging so that you can collect any stacktraces of interest from the kernel.

# Details #

Create a new unprivileged user account.

```
# adduser "untrusted"
# id -a untrusted
uid=502(untrusted) gid=503(untrusted) groups=503(untrusted)
```

Build an iknowthis binary and make it accessible to the untrusted user.

```
# su - untrusted -c /path/to/iknowthis
** Message: welcome to iknowthis, a linux system call fuzzer, pid  2188
```