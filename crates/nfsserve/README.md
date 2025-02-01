Rust NFSv3 Server
=================
This is an incomplete but very functional implementation of an NFSv3 server
in Rust.

Why? You may ask. 

I wanted to implement a user-mode file-system mount that is truly cross-platform.
What is a protocol that pretty much every OS supports? NFS.

Why not FUSE you may ask:
1. FUSE is annoying to users on Mac and Windows (drivers necessary).
2. It takes a lot of care to build a FUSE driver for remote filesystems. 
NFS clients however have a lot of historical robustification for
slow-responding, or perhaps, never-responding servers. 
3. The OS is pretty good at caching NFS. There are established principles for 
cache eviction, for metadata, or for data. With a FUSE driver I have to do
a lot of the work myself.

So, this is a FUSE-like user-mode filesystem API that basically works by 
creating a localhost NFSv3 server you can mount.

This is used in [pyxet](https://github.com/xetdata/pyxet) and 
[xet-core](https://github.com/xetdata/xet-core/) to provide the `xet mount`
functionality that allows you to mount multi-TB [Xethub](https://about.xethub.com) repository
anywhere.

This is a blogpost explaining our rationale: https://about.xethub.com/blog/nfs-fuse-why-we-built-nfs-server-rust

Run the Demo
============
To run the demofs, this will host an NFS server on localhost:11111
```
cargo build --example demo --features demo
./target/debug/examples/demo
```

To mount. On Linux (sudo may be required):
```
mkdir demo
mount.nfs -o user,noacl,nolock,vers=3,tcp,wsize=1048576,rsize=131072,actimeo=120,port=11111,mountport=11111 localhost:/ demo
```

On Mac:
```
mkdir demo
mount_nfs -o nolocks,vers=3,tcp,rsize=131072,actimeo=120,port=11111,mountport=11111 localhost:/ demo
```

On Windows (Pro required as Home does not have NFS client):
```
mount.exe -o anon,nolock,mtype=soft,fileaccess=6,casesensitive,lang=ansi,rsize=128,wsize=128,timeout=60,retry=2 \\127.0.0.1\\ X:
```

Note that the demo filesystem is *writable*. 

Usage
=====

You simply need to implement the vfs::NFSFileSystem
trait. See demofs.rs for an example and bin/main.rs for how to actually start
a service. The interface generally not difficult to implement; demanding mainly
the ability to associate every file system object (directory/file) with a 64-bit
ID. Directory listing can be a bit complicated due to the pagination requirements.

TODO and Seeking Contributors
=============================
 - Improve documentation
 - More things in Mount Protocol and NFS Protocol has to be implemented.
 There are a bunch of messages that reply as "Unavailable". For instance, 
 we implement `READDIR_PLUS` but not `READDIR` which is usually fine, except
 that Windows insists on always trying READDIR first. 
 Link creation is also not supported.
 - The RPC message handling in `nfs_handlers.rs` leaves a lot to be desired.
 The response serialization is very manual. Some cleanup will be good.
 - Windows mount "kinda" works (only on Windows 11 Pro with the NFS server),
 but prints a lot of garbage due to various unimplemented APIs. Windows 11
 somehow tries to poll with very old NFS protocols constantly.
 - Many many perf optimizations. 
 - Maybe pull in the mount command from [xet-core](https://github.com/xetdata/xet-core/blob/main/rust/gitxetcore/src/xetmnt/mod.rs)
 so the user does not need to remember the `-o` incantations above.
 - Maybe make an SMB3 implementation so we can work on Windows Home edition
 - NFSv4 has some write performance optimizations that would be quite nice.
 The protocol is a bit more involving to implement though as it is somewhat
 stateful.

Relevant RFCs
=============
 - XDR is the message format: RFC 1014. https://datatracker.ietf.org/doc/html/rfc1014
 - SUN RPC is the RPC wire format: RFC 1057 https://datatracker.ietf.org/doc/html/rfc1057
 - NFS is at RFC 1813 https://datatracker.ietf.org/doc/html/rfc1813
 - NFS Mount Protocol is at RFC 1813 Appendix I. https://datatracker.ietf.org/doc/html/rfc1813#appendix-I
 - PortMapper is at RFC 1057 Appendix A https://datatracker.ietf.org/doc/html/rfc1057#appendix-A

Basic Source Layout
===================
 - context.rs: A connection context object that is passed around containing
 connection information, VFS information, etc.
 - xdr.rs: Serialization / Deserialization routines for XDR structures
 - tcp.rs: Main TCP handling entry point
 - rpcwire.rs: Reads and write RPC messages from a TCP socket and performs outer 
               most RPC message decoding, redirecting to NFS/Mount/Portmapper 
               implementations as needed.
 - rpc.rs: The structure of a RPC call and reply. All XDR encoded.
 - portmap.rs/portmap\_handlers.rs: The XDR structures required by the Portmapper protocol and the Portmapper RPC handlers.
 - mount.rs/mount\_handlers.rs: The XDR structures required by the Mount protocol and the Mount RPC handlers.
 - nfs.rs/nfs\_handlers.rs: The XDR structures required by the NFS protocol and the NFS RPC handlers.


More More Details Than Necessary
================================
The basic way a message works is:
1. We read a collection of fragments off a TCP stream 
(a 4 byte length header followed by a bunch of bytes)
2. We assemble the fragments into a record
3. The Record is of a SUN RPC message type.
4. A message tells us 3 pieces of information,
     - The RPC Program (just an integer denoting
      a protocol "class". For instance NFS protocol is 100003, the Portmapper protocol is 100000).
     - The version of the RPC program (ex: 3 = NFSv3, 4 = NFSv4, etc)
     - The method invoked (Which NFS method to call) (See for instance nfs.rs top comment for the list)
5. Continuing to decode the message will give us the arguments of the method
6. And we take the method response, wrap it around a record and return it. 

Portmapper
----------
First, lets get portmapper out of the way. This is a *very* old mechanism which
is rarely used anymore. The portmapper is a daemon which runs on a machine running
on port 111. When NFS, or other RPC services start, they register with the 
portmapper service with the port they are listening on (Say NFS on 2049). 
Then when another machine wants to connect to NFS, they first ask the port mapper
on 111 to ask about which port NFS is listening on, then connects to the returned 
port.

We do not strictly need to implement this protocol as this is pretty much
unused these days (NFSv4 does not use the portmapper for instance). If `-o port` and `-o mountport`
are specified, Linux and Mac's builtin NFS client do not need it either.
But this was useful for debugging and testing as libnfs seems to require a
portmapper, but it annoyingly hardcodes it to 111. I modified the source to
change it to 12000 for testing and implemented the one `PMAPPROC_GETPORT`
method so I can test with libnfs.


NFS Basics
==========
The way NFS works is that every file system object (dir/file/symlink) has 2
ways in which it can be addressed:

1. `fileid3: u64` . A 64-bit integer. Equivalent to an inode number.
2. `nfs_fh3`: A variable opaque object up to 64 bytes long.

Basically anytime the client tries to access any information about an object,
it needs an `nfs_fh3`. The purpose of the `nfs_fh3` serves 2 purposes:

 - Allow server to cache additional query information in the handle that may exceed
 64-bit. For instance if the server has multiple exports on different disk volumes,
 I may need a few more bits to identify the disk volume.
 - Allow client to identify when server has "restarted" and thus client has to
 clear all caches. the `nfs_fh3` handle should contain a token that is unique
 to when the NFS server first started up which allows the server to check that
 the handle is still valid. If the server has restarted, all previous handles
 will therefore be "expired" and any usage of them should trigger a handle expiry
 error informing the clients to expunge all caches.


However, the only way to obtain an `nfs_fh3` for a file is via directory traversal.
i.e. There is a lookup method 
`LOOKUP(directory's handle, filename of file/dir in directory)` 
which returns the handle for the filename.

For instance to get the handle of a file "dir/a.txt", I first need the handle
for the directory "dir/", then query `LOOKUP(handle, "a.txt")`.

The question is then, how do I get my first handle? That is what the MOUNT
protocol addresses.

Mount
-----
The MOUNT protocol provides a list of "exports", (in the simplest case. Just "/")
and the client will request to MNT("/") which will return the handle of this 
root directory.

Normally the server can and do maintain a list of mounts which can be queried,
and really the client can UMNT (unmount) as well.  But in our case we
only implement MNT and EXPORT which suffices. NFS clients generally
ignore the return message of UMNT as there is really nothing the
client can do on a UMNT failure. As such our Mount protocol implementation
is entirely stateless.

NFS
---
The NFS protocol itself is pretty straightforward with most annoyances
due to handling of the XDR messaging format (in paticular with optional,
lists, etc).

What is nice is that the design of NFS is completely stateless. It is mostly
sit down and implement all the methods that are hit and test them against a 
client.
