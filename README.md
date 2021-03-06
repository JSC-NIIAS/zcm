## [Explore the web-based readme](http://zerocm.github.io/zcm/)
[![Build Status](https://travis-ci.org/ZeroCM/zcm.svg?branch=master)](https://travis-ci.org/ZeroCM/zcm)

# ZCM: Zero Communications and Marshalling
## Installation
To install ZCM correctly (with ```--use-all``` flag), you should make some preparations with you system
1. Install packages 
```
sudo apt-get install cython3 python3-dev python3-pip python-dev cython openjdk-8-jre openjdk-8-jdk libelf1 libelf-dev npm nodejs gcc-5 g++-5
```
2. Build and install ZeroMQ
````
cd <your workspace directory>
wget https://github.com/zeromq/zeromq4-1/releases/download/v4.1.6/zeromq-4.1.6.tar.gz --no-check-certificate
tar -xvzf zeromq-4.1.6.tar.gz
cd zeromq-4.1.6/
./configure
make -j6 # Instead of "6" you should set your number of CPU cores 
sudo make install
````
3. Build and install ZeroCM
```
cd <your workspace directory>
git clone http://192.168.0.203:17990/scm/elsd/zcm.git -b release --recursive
cd zcm
sudo su
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64/
CXX=/usr/bin/g++-5 CC=/usr/bin/gcc-5 ./waf configure --use-all --use-third-party
CXX=/usr/bin/g++-5 CC=/usr/bin/gcc-5 ./waf build
CXX=/usr/bin/g++-5 CC=/usr/bin/gcc-5 ./waf install
exit
```
If you need to install zcm on other target, you should change your architecture
```
# example: arm64
export JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-arm64
```
Before next command you should check you current directory. It has to be ```<your workspace directory>/zcm```
```
pip3 install zcm/python
```
If you see an ```setuptools``` error - execute the next command and repeat the command above
```
pip3 install setuptools
```
4. Check your installation:
    4.1 Python
    ```
    python3
    import zero_cm as zcm
    ```
    4.2 Java
    ```
    zcm-logplayer-gui -u ipc
    ```
    If you see a ```java``` error - please set your runtime java version to 8 instead of 11
    ```
    update-alternatives --config java
    ```
## Description
# ZCM: Zero Communications and Marshalling

ZCM is a micro-framework for message-passing and data-marshalling, designed originally
for robotics systems where high-bandwidth and low-latency are critical and the variance in
compute platforms is large.

ZCM is a publish/subscribe message-passing system with automatic message type-checking and
serialization. It provides bindings for a variety of programming languages, and generates
language-specific message serialization routines. Using a ZCM message feels natural
in each language.

ZCM is transport-agnostic. There is no required built-in transport. Every transport is
first-class. This is achieved by defining strict blocking and non-blocking transport APIs. As
long as a transport implementation conforms to this API, it should work flawlessly with ZCM.
This design allows ZCM to work well on anything from a high-end posix-based compute cluster
with thousands of nodes to a low-end real-time embedded-system with no operating system.

ZCM is a derivation of the [LCM project](http://lcm-proj.github.io/) created in 2006 by
the MIT DARPA Urban Challenge team. The core message-type system, publish/subscribe APIs,
and basic tools are ported directly from LCM and remain about 95% compatible. While there
are a handful of subtle differences between the two, the core distinguishing feature is
ZCM's transport agnosticism. LCM is designed completely around UDP Multicast. This transport
makes a lot of sense for LAN connected compute clusters (such the original 2006 MIT DGC
Vechicle).  However, there are many other applications that are interesting targets for
ZCM messaging.  These include: local system messaging (IPC), multi-threaded messaging
(in-process), embedded-system peripherals (UART, I2C, etc), and web applications
(Web Sockets).  By refusing to make hard assumptions about the transport layer, ZCM opens
the door to a wide set of use-cases that were neither possible nor practical with LCM.

To learn more about what ZCM tries to be, and its guiding principles, check out the
[Project Philosphy](docs/philosophy.md).

To dive, in and see some examples, check out the [Tutorial](docs/tutorial.md).

If you have previously used LCM, check out [From LCM to ZCM](docs/lcm_to_zcm.md).

To learn how you can contribute to this project, check out [Contributing](docs/contributing.md)

## Quick Links
 - [Project Philosphy](docs/philosophy.md)
 - [Tutorial](docs/tutorial.md)
 - [From LCM to ZCM](docs/lcm_to_zcm.md)
 - [ZCM Type System](docs/zcmtypesys.md)
 - [Transport Layer](docs/transports.md)
 - [Embedded Applications](docs/embedded.md)
 - Web Applications (coming soon)
 - [Dependencies & Building](docs/building.md)
 - [Tools](docs/tools.md)
 - [Frequently Asked Questions](docs/FAQs.md)
 - [Continuous Integration](http://ci.zcm-project.org)
 - [Contributing](docs/contributing.md)

## Features
 - Type-safe and version-safe message serialization
 - A useful suite of tools for logging, log-playback, and real-time message inspection (spy)
 - A wide set of optionally built-in transports including UDP Multicast, IPC, In-Process, Serial, and ZeroMQ
 - A well-defined interface for building custom transports
 - Strong support for embedded applications. The core embedded code is restricted to C89.
 - Only one true dependency: A modern C++11 compiler for the non-embedded code.

## Supported platforms and languages
 - Platforms
  - GNU/Linux
  - Web browsers supporting the Websocket API
  - Any C89 capable embedded system
 - Languages
  - C89 and greater
  - C++
  - Java
  - MATLAB (using Java)
  - NodeJS and Client-side Javascript
  - Python

## Roadmap
 - Platform Support
   - Windows
   - OS X
   - Any POSIX-1.2001 system (e.g., Cygwin, Solaris, BSD, etc.)
 - Consider porting the rest of the LCM languages
   - C#
   - Lua
 - Explore alternative messaging paradigms using ZCM Types (e.g. those found in ZeroMQ)
 - Break from the original LCM APIs to improve API consistency
   - Goal for v2.0
   - v1.0 will **always** strive for API compatibility

## Subtle differences to LCM

ZCM is approximately 95% API compatible with LCM. Porting existing Unix-based LCM
programs to ZCM is very easy in many cases. A quick `sed -i 's/lcm/zcm/g'` works for
most applications. ZCM uses the same binary-compatible formats for UDP Multicast, Logging,
and ZCMType encodings. Thus LCM and ZCM applications can communicate flawlessly. This
allows LCM users to gradually migrate to ZCM.

### Known incompatibilities:
 - `zcm_get_fileno()` is not supported
 - `zcm_handle_timeout()` is not supported
 - Any applications using GLib via LCM may have build errors
   - ZCM does *not* depend on GLib
 - ZCMType drops support for the LCMType-style enums
