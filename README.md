# kasync
cross platform high performance async IO libary. 
* support linux/freebsd/windows system.
* linux use epoll/io_uring, bsd use kqueue, windows use iocp.
* ssl/tls support.
* fiber support
* async socket and file
* support sendfile/SSL_sendfile
* thread pool