
# Multithreaded HTTP Server in C

A lightweight, multithreaded HTTP server implemented in C using POSIX sockets and pthreads. This server runs on Linux, serves static files, and supports URI-based routing. It is designed for educational and practical use, demonstrating core concepts of network programming, concurrency, and HTTP protocol handling.

---

## Demo
The project is deployed on [AWS](http://ec2-3-111-86-156.ap-south-1.compute.amazonaws.com:6970/)

Watch the demo (It takes some time to load or go to the demo_video folder ) ->
![Demo GIF](demo_video/server.gif)

## Stress Testing

Stress tested via Apache Bench with n=10,000 and c=20 -> 

![Stress_Test GIF](demo_video/http%20server%20stress%20test.gif)

Kcachegrind call map->

<img src="demo_video/kcache_http_img.png">


## Features

- **POSIX Sockets**: Handles TCP connections using the standard Linux socket API.
- **Multithreaded**: Uses pthreads to process multiple client requests concurrently.
- **Static File Serving**: Delivers HTML, JPEG, CSS, JavaScript and other static files from a specified directory.
- **URI-Based Routing**: Maps incoming HTTP requests to files or handler functions based on the URI.
- **HTTP/1.0 Support**: Implements the GET and HEAD methods, responding to invalid requests with proper error messages.
- **Linux Only**: Developed and tested on Linux systems.

---

## References

- **Beej's Guide to Network Programming**
[Beej's Guide to Network Programming (Official Site)](https://beej.us/guide/bgnet/pdf/bgnet_a4_c_1.pdf)
- **Arch Linux Networking Man Pages**
[socket(7) - Sockets API Overview](https://man.archlinux.org/man/socket.7.en)
[tcp(7) - TCP Protocol](https://man.archlinux.org/man/tcp.7.en)
[udp(7) - UDP Protocol](https://man.archlinux.org/man/udp.7.en)
[epoll(7) - epoll API](https://man.archlinux.org/man/epoll.7.en)
[select(2) - I/O Multiplexing](https://man.archlinux.org/man/select.2.en)
[poll(2) - I/O Multiplexing](https://man.archlinux.org/man/poll.2.en)
[accept(2) - Accept Connections](https://man.archlinux.org/man/accept.2.en)
[bind(2) - Bind Socket](https://man.archlinux.org/man/bind.2.en)
[connect(2) - Connect Socket](https://man.archlinux.org/man/connect.2.en)
[listen(2) - Listen for Connections](https://man.archlinux.org/man/listen.2.en)
[send(2) - Send Data](https://man.archlinux.org/man/send.2.en)
[recv(2) - Receive Data](https://man.archlinux.org/man/recv.2.en)
[shutdown(2) - Shutdown Connection](https://man.archlinux.org/man/shutdown.2.en)
- **Book Reference**
Douglas Comer - Internetworking with TCP/IP
<img src="./demo_video/book.jpeg">

## Installation

### Prerequisites

- GCC (GNU Compiler Collection)
- GNU Make
- Linux OS
- POSIX pthreads library (usually included by default)


### Clone the Repository

```bash
git clone https://github.com/harsh-panchal-804/HTTP-Server-in-C

```



---

## Build and Run

### Build

Compile the server using the provided Makefile:

```bash
make
```


### Run

Start the server with:

```bash
./server
```

By default, the server listens on a specified port (e.g., 6970). You can access it from your browser or with tools like `curl`:

```
http://localhost:6970/
```

## Usage

- Place your static files (e.g., HTML, JPEG) in the server's root directory.
- The server will map URIs to files (e.g., `/about.html` serves `about.html` from the root).
- The server can handle multiple connections.
- Error responses are sent as HTML for easy debugging in browsers.

---


## Project Structure

- `server.c` – Main server implementation (sockets, threads, routing)
- `Makefile` – Build instructions
- `README.md` – Project documentation

---

## License

This project is open-source. See the `LICENSE` file for details.

---

## Contributing

Pull requests and suggestions are welcome! Please open an issue to discuss changes or report bugs.

---

