#pragma once
#include <zcm/transport/udpm/udpm.hpp>
#include <zcm/transport/udpm/buffers.hpp>

class UdpdAddress
{
public:

    UdpdAddress() = default;

    UdpdAddress(const string& ip, u16 port)
    {
        this->ip = ip;
        this->port = port;

        memset(&this->addr, 0, sizeof(this->addr));
        this->addr.sin_family = AF_INET;
        inet_aton(ip.c_str(), &this->addr.sin_addr);
        this->addr.sin_port = port;
    }

    const string& getIP() const { return ip; }
    u16 getPort() const { return port; }
    struct sockaddr* getAddrPtr() const { return (struct sockaddr*)&addr; }
    size_t getAddrSize() const { return sizeof(addr); }

private:
    string ip;
    u16 port;
    struct sockaddr_in addr;
};

class UdpdSocket
{
  public:
    UdpdSocket();
    ~UdpdSocket();
    bool isOpen();
    void close();

    bool init();
    bool setTTL(u8 ttl);
    bool bindAdress(in_addr ipaddr, string ip, u16 port);
    bool setReuseAddr();
    bool setReusePort();
    bool enablePacketTimestamp();

    size_t getRecvBufSize();
    size_t getSendBufSize();

    // Returns true when there is a packet available for receiving
    bool waitUntilData(int timeout);
    int recvPacket(Packet *pkt);

    ssize_t sendBuffers(const UdpdAddress& dest, const char *a, size_t alen);
    ssize_t sendBuffers(const UdpdAddress& dest, const char *a, size_t alen,
                        const char *b, size_t blen) const;
    ssize_t sendBuffers(const UdpdAddress& dest, const char *a, size_t alen,
                        const char *b, size_t blen, const char *c, size_t clen) const;

    static bool checkConnection(const string& ip, u16 port);
    void checkAndWarnAboutSmallBuffer(size_t datalen, size_t kbufsize);

    static UdpdSocket createSendSocket(std::string ip, u16 port, u8 ttl);
    static UdpdSocket createRecvSocket(struct in_addr ipaddr, string ip, u16 port);

    UdpdAddress dst_addr;

  private:
    SOCKET fd = -1;
    bool warnedAboutSmallBuffer = false;

  private:
    // Disallow copies
    UdpdSocket(const UdpdSocket&) = delete;
    UdpdSocket& operator=(const UdpdSocket&) = delete;

  public:
    // Allow moves
    UdpdSocket(UdpdSocket&& other) { std::swap(this->fd, other.fd); }
    UdpdSocket& operator=(UdpdSocket&& other) { std::swap(this->fd, other.fd); return *this; }
};
