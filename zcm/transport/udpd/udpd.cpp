#include <zcm/transport/udpm/buffers.hpp>
#include <zcm/transport/udpm/mempool.hpp>

#include <zcm/transport/udpd/udpd.hpp>
#include <zcm/transport/udpd/udpdsocket.hpp>

#include <zcm/transport.h>
#include <zcm/transport_registrar.h>
#include <zcm/transport_register.hpp>


#define MTU (1<<28)

static i32 utimeInSeconds()
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (i32)tv.tv_sec;
}

/**
 * UDPD_params_t:
 * @addr:        ip address
 * @port:        ip port
 * @ttl:         if 0, then packets never leave local host.
 *                  if 1, then packets stay on the local network
 *                        and never traverse a router
 *                  don't use > 1.  that's just rude.
 * @recv_buf_size:  requested size of the kernel receive buffer, set with
 *                  SO_RCVBUF.  0 indicates to use the default settings.
 *
 */



struct UDPD
{

    std::thread keep_alive_watchguard;
    std::mutex keep_alive_lock;

    struct Params
    {
        UdpdAddress src_udpd_address;

        struct in_addr src_addr;

        u8             ttl;
        u8             keep_alive;
        size_t         recv_buf_size;

        Params(UdpdAddress& src_address, size_t recv_buf_size, u8 ttl, u8 keep_alive) {
            src_udpd_address = src_address;

            // TODO verify that the IP and PORT are vaild
            inet_aton(src_udpd_address.getIP().c_str(), (struct in_addr*) &this->src_addr);

            this->recv_buf_size = recv_buf_size;
            this->ttl = ttl;
            this->keep_alive = keep_alive;
        }
    };

    Params params;

    UdpdSocket recvfd;

    std::map<std::string, std::pair<UdpdSocket, uint64_t>> dst_sock_pool;

    /* size of the kernel UDPD receive buffer */
    size_t kernel_rbuf_sz = 0;
    size_t kernel_sbuf_sz = 0;
    bool warned_about_small_kernel_buf = false;

    MessagePool pool {MAX_FRAG_BUF_TOTAL_SIZE, MAX_NUM_FRAG_BUFS};

    /* other variables */
    u32          udpd_rx = 0;            // packets received and processed
    u32          udpd_discarded_bad = 0; // packets discarded because they were bad
                                    // somehow
    double       udpd_low_watermark = 1.0; // least buffer available
    i32          udpd_last_report_secs = 0;

    u32          msg_seqno = 0; // rolling counter of how many messages transmitted

    /***** Methods ******/
    UDPD(Params params);
    bool init();
    ~UDPD();

    int handle();

    int sendmsg(zcm_msg_t msg);
    int recvmsg(zcm_msg_t *msg, int timeout);

  private:
    // These returns non-null when a full message has been received
    Message *recvShort(Packet *pkt, u32 sz);
    Message *recvFragment(Packet *pkt, u32 sz);
    Message *readMessage(int timeout);

    Message *m = nullptr;

    bool selftest();
    void checkForMessageLoss();
};

Message *UDPD::recvShort(Packet *pkt, u32 sz)
{
    MsgHeaderShort *hdr = pkt->asHeaderShort();

    size_t clen = hdr->getChannelLen();
    if (clen > ZCM_CHANNEL_MAXLEN) {
        ZCM_DEBUG("bad channel name length");
        udpd_discarded_bad++;
        return NULL;
    }

    udpd_rx++;

    Message *msg = pool.allocMessageEmpty();
    msg->utime = pkt->utime;
    msg->channel = hdr->getChannelPtr();
    msg->channellen = clen;
    msg->data = hdr->getDataPtr();
    msg->datalen = hdr->getDataLen(sz);
    pool.moveBuffer(msg->buf, pkt->buf);

    return msg;
}

Message *UDPD::recvFragment(Packet *pkt, u32 sz)
{
    MsgHeaderLong *hdr = pkt->asHeaderLong();

    // any existing fragment buffer for this message source?
    FragBuf *fbuf = pool.lookupFragBuf((struct sockaddr_in*)&pkt->from);

    u32 msg_seqno = hdr->getMsgSeqno();
    u32 data_size = hdr->getMsgSize();
    u32 fragment_offset = hdr->getFragmentOffset();
    u16 fragment_no = hdr->getFragmentNo();
    u16 fragments_in_msg = hdr->getFragmentsInMsg();
    u32 frag_size = hdr->getFragmentSize(sz);
    char *data_start = hdr->getDataPtr();

    // discard any stale fragments from previous messages
    if (fbuf && ((fbuf->msg_seqno != msg_seqno) ||
                 (fbuf->buf.size != data_size + fbuf->channellen+1))) {
        pool.removeFragBuf(fbuf);
        ZCM_DEBUG("Dropping message (missing %d fragments)", fbuf->fragments_remaining);
        fbuf = NULL;
    }

    if (data_size > MTU) {
        ZCM_DEBUG("rejecting huge message (%d bytes)", data_size);
        return NULL;
    }

    // create a new fragment buffer if necessary
    if (!fbuf && fragment_no == 0) {
        char *channel = (char*) (hdr + 1);
        int channel_sz = strlen(channel);
        if (channel_sz > ZCM_CHANNEL_MAXLEN) {
            ZCM_DEBUG("bad channel name length");
            udpd_discarded_bad++;
            return NULL;
        }

        fbuf = pool.addFragBuf(channel_sz + 1 + data_size);
        fbuf->last_packet_utime = pkt->utime;
        fbuf->msg_seqno = msg_seqno;
        fbuf->fragments_remaining = fragments_in_msg;
        fbuf->channellen = channel_sz;
        fbuf->from = *(struct sockaddr_in*)&pkt->from;
        memcpy(fbuf->buf.data, data_start, frag_size);

        --fbuf->fragments_remaining;
        return NULL;
    }

    if (!fbuf) return NULL;
    recvfd.checkAndWarnAboutSmallBuffer(data_size, kernel_rbuf_sz);

    if (fbuf->channellen+1 + fragment_offset + frag_size > fbuf->buf.size) {
        ZCM_DEBUG("dropping invalid fragment (off: %d, %d / %zu)",
                fragment_offset, frag_size, fbuf->buf.size);
        pool.removeFragBuf(fbuf);
        return NULL;
    }

    // copy data
    memcpy(fbuf->buf.data + fbuf->channellen+1 + fragment_offset, data_start, frag_size);

    fbuf->last_packet_utime = pkt->utime;
    if (--fbuf->fragments_remaining > 0)
        return NULL;

    // we've received all the fragments, return a new Message
    Message *msg = pool.allocMessageEmpty();
    msg->utime = fbuf->last_packet_utime;
    msg->channel = fbuf->buf.data;
    msg->channellen = fbuf->channellen;
    msg->data = fbuf->buf.data + fbuf->channellen + 1;
    msg->datalen = fbuf->buf.size - (fbuf->channellen + 1);
    pool.moveBuffer(msg->buf, fbuf->buf);

    // don't need the fragment buffer anymore
    pool.removeFragBuf(fbuf);

    return msg;
}

void UDPD::checkForMessageLoss()
{
    // ISSUE-101 TODO: add this back
    // TODO warn about message loss somewhere else.
    // u32 ring_capacity = ringbuf->get_capacity();
    // u32 ring_used = ringbuf->get_used();

    // double buf_avail = ((double)(ring_capacity - ring_used)) / ring_capacity;
    // if (buf_avail < udpd_low_watermark)
    //     udpd_low_watermark = buf_avail;

    // i32 tm = utimeInSeconds();
    // int elapsedsecs = tm - udpd_last_report_secs;
    // if (elapsedsecs > 2) {
    //    if (udpd_discarded_bad > 0 || udpd_low_watermark < 0.5) {
    //        fprintf(stderr,
    //                "%d ZCM loss %4.1f%% : %5d err, "
    //                "buf avail %4.1f%%\n",
    //                (int) tm,
    //                udpd_discarded_bad * 100.0 / (udpd_rx + udpd_discarded_bad),
    //                udpd_discarded_bad,
    //                100.0 * udpd_low_watermark);

    //        udpd_rx = 0;
    //        udpd_discarded_bad = 0;
    //        udpd_last_report_secs = tm;
    //        udpd_low_watermark = HUGE;
    //    }
    // }
}

// read continuously until a complete message arrives
Message *UDPD::readMessage(int timeout)
{
    Packet *pkt = pool.allocPacket(ZCM_MAX_UNFRAGMENTED_PACKET_SIZE);
    UDPD::checkForMessageLoss();

    Message *msg = NULL;
    while (!msg) {
        // // wait for either incoming UDP data, or for an abort message
        if (!recvfd.waitUntilData(timeout))
            break;

        int sz = recvfd.recvPacket(pkt);

        // working only with IPV4. IPV6 removed in case of optimization
        auto from_sa_in = reinterpret_cast<sockaddr_in*>(&pkt->from);
        std::string ip(inet_ntoa(from_sa_in->sin_addr));
        u16 port =  htons (from_sa_in->sin_port);

        std::string ip_port = ip + ":" + std::to_string(port);

        if ( dst_sock_pool.count(ip_port) > 0) {
            // update socket timestamp to keep alive
            dst_sock_pool[ip_port].second = pkt->utime;
        } else {
            // add socket to pool
            dst_sock_pool[ip_port] = {UdpdSocket::createSendSocket(ip, port, params.ttl), pkt->utime};
            ZCM_DEBUG("Added to pool: %s", ip_port.c_str());
        }

        if (sz < 0) {
            ZCM_DEBUG("udpd_read_packet -- recvmsg");
            udpd_discarded_bad++;
            continue;
        }

        ZCM_DEBUG("Got packet of size %d", sz);

        if (sz < (int)sizeof(MsgHeaderShort)) {
            // packet too short to be ZCM
            udpd_discarded_bad++;
            continue;
        }

        u32 magic = pkt->asHeaderShort()->getMagic();
        if (magic == ZCM_MAGIC_SHORT)
            msg = recvShort(pkt, sz);
        else if (magic == ZCM_MAGIC_LONG)
            msg = recvFragment(pkt, sz);
        else {
            ZCM_DEBUG("ZCM: bad magic");
            udpd_discarded_bad++;
            continue;
        }
    }

    pool.freePacket(pkt);
    return msg;
}

int UDPD::sendmsg(zcm_msg_t msg)
{
    int channel_size = strlen(msg.channel);
    if (channel_size > ZCM_CHANNEL_MAXLEN) {
        fprintf(stderr, "ZCM Error: channel name too long [%s]\n", msg.channel);
        return ZCM_EINVALID;
    }

    int payload_size = channel_size + 1 + msg.len;
    if (payload_size <= ZCM_SHORT_MESSAGE_MAX_SIZE) {
        // message is short.  send in a single packet

        MsgHeaderShort hdr;
        hdr.setMagic(ZCM_MAGIC_SHORT);
        hdr.setMsgSeqno(msg_seqno);

        for (auto& dst : dst_sock_pool) {

            auto udpd_sock = std::move(dst.second.first);
            udpd_sock.sendBuffers(udpd_sock.dst_addr,
                                  (char*)&hdr, sizeof(hdr),
                                  (char*)msg.channel, channel_size+1,
                                  (char*)msg.buf, msg.len);

            uint64_t packet_size = sizeof(hdr) + payload_size;
            ZCM_DEBUG("transmitting %zu byte [%s] payload (%ld byte pkt) to %s",
                      msg.len, msg.channel, packet_size, dst.first.c_str());
        }

        msg_seqno++;

        return 0;

    } else {
        // message is large.  fragment into multiple packets
        int fragment_size = ZCM_FRAGMENT_MAX_PAYLOAD;
        int nfragments = payload_size / fragment_size + (payload_size % fragment_size != 0);

        if (nfragments > 65535) {
            fprintf(stderr, "ZCM error: too much data for a single message\n");
            return -1;
        }

        // acquire transmit lock so that all fragments are transmitted
        // together, and so that no other message uses the same sequence number
        // (at least until the sequence # rolls over)

        ZCM_DEBUG("transmitting %d byte [%s] payload in %d fragments",
                  payload_size, msg.channel, nfragments);

        u32 fragment_offset = 0;

        MsgHeaderLong hdr;
        hdr.magic = htonl(ZCM_MAGIC_LONG);
        hdr.msg_seqno = htonl(msg_seqno);
        hdr.msg_size = htonl(msg.len);
        hdr.fragment_offset = 0;
        hdr.fragment_no = 0;
        hdr.fragments_in_msg = htons(nfragments);

        // first fragment is special.  insert channel before data
        size_t firstfrag_datasize = fragment_size - (channel_size + 1);
        assert(firstfrag_datasize <= msg.len);

        //uint64_t packet_size = sizeof(hdr) + (channel_size + 1) + firstfrag_datasize;
        fragment_offset += firstfrag_datasize;

        for (auto& dst : dst_sock_pool) {

            auto udpd_sock = std::move(dst.second.first);
            ssize_t status = udpd_sock.sendBuffers(udpd_sock.dst_addr,
                                                   (char*)&hdr, sizeof(hdr),
                                                   (char*)msg.channel, channel_size+1,
                                                   (char*)msg.buf, msg.len);

            uint64_t packet_size = sizeof(hdr) + payload_size;
            ZCM_DEBUG("transmitting %zu byte [%s] payload (%ld byte pkt) to %s",
                      msg.len, msg.channel, packet_size, dst.first.c_str());

            // transmit the rest of the fragments
            for (u16 frag_no = 1; packet_size == (uint64_t)(status) && frag_no < nfragments; frag_no++) {
                hdr.fragment_offset = htonl(fragment_offset);
                hdr.fragment_no = htons(frag_no);

                int fraglen = std::min(fragment_size, (int)msg.len - (int)fragment_offset);
                status = udpd_sock.sendBuffers(udpd_sock.dst_addr,
                                            (char*)&hdr, sizeof(hdr),
                                            (char*)(msg.buf + fragment_offset), fraglen);

                fragment_offset += fraglen;
                packet_size = sizeof(hdr) + fraglen;
            }

            // sanity check
            if (0 == status) {
                assert(fragment_offset == msg.len);
            }

        }

        msg_seqno++;
    }

    return 0;
}

int UDPD::recvmsg(zcm_msg_t *msg, int timeout)
{
    if (m)
        pool.freeMessage(m);

    m = readMessage(timeout);
    if (m == nullptr)
        return ZCM_EAGAIN;

    msg->utime = m->utime;
    msg->channel = m->channel;
    msg->len = m->datalen;
    msg->buf = (uint8_t*) m->data;

    return ZCM_EOK;
}

UDPD::~UDPD()
{
    ZCM_DEBUG("closing zcm context");
}

UDPD::UDPD(Params params)
    : params(params)
{
}

bool UDPD::init()
{
    ZCM_DEBUG("Initializing ZCM UDPD context...");
    ZCM_DEBUG("Source address %s:%d", params.src_udpd_address.getIP().c_str(), params.src_udpd_address.getPort());

    recvfd = UdpdSocket::createRecvSocket(params.src_addr, params.src_udpd_address.getIP(), params.src_udpd_address.getPort());
    if (!recvfd.isOpen()) return false;
    kernel_rbuf_sz = recvfd.getRecvBufSize();

    if (!this->selftest()) {
        // self test failed.  destroy the read thread
        fprintf(stderr, "ZCM self test failed!!\n"
                "Check your routing and firewall settings\n");
        return false;
    }

    if (params.keep_alive > 0) {

        keep_alive_watchguard = std::thread([&]() {

            while (true) {

                keep_alive_lock.lock();

                uint64_t now_us = std::chrono::duration_cast<std::chrono::
                        microseconds>(std::chrono::high_resolution_clock::
                        now().time_since_epoch()).count();

                uint64_t timestamp;

                for (auto &dst : dst_sock_pool) {
                    timestamp = dst.second.second;

                    if ((now_us - timestamp) / 1000000 > params.keep_alive) {
                        ZCM_DEBUG("Deleted from pool: %s", dst.first.c_str());
                        dst_sock_pool.erase(dst.first);
                    }
                }

                keep_alive_lock.unlock();

                // check for keep alive every second
                sleep(1);
            }
        });

        keep_alive_watchguard.detach();
    }

    return true;
}

bool UDPD::selftest()
{
#ifdef ENABLE_SELFTEST
    ZCM_DEBUG("UDPD conducting self test");
    assert(0 && "unimpl");
#endif
    return true;
}

// Define this the class name you want
#define ZCM_TRANS_CLASSNAME TransportUDPD

struct ZCM_TRANS_CLASSNAME : public zcm_trans_t
{
    UDPD udpd;

    ZCM_TRANS_CLASSNAME(const UDPD::Params params)
        : udpd(params)
    {
        auto a = params;
        trans_type = ZCM_BLOCKING;
        vtbl = &methods;
    }

    bool init() { return udpd.init(); }

    /********************** STATICS **********************/
    static zcm_trans_methods_t methods;
    static ZCM_TRANS_CLASSNAME *cast(zcm_trans_t *zt)
    {
        assert(zt->vtbl == &methods);
        return (ZCM_TRANS_CLASSNAME*)zt;
    }

    static size_t _getMtu(zcm_trans_t *zt)
    { return MTU; }

    static int _sendmsg(zcm_trans_t *zt, zcm_msg_t msg)
    { return cast(zt)->udpd.sendmsg(msg); }

    static int _recvmsgEnable(zcm_trans_t *zt, const char *channel, bool enable)
    { return ZCM_EOK; }

    static int _recvmsg(zcm_trans_t *zt, zcm_msg_t *msg, int timeout)
    { return cast(zt)->udpd.recvmsg(msg, timeout); }

    static void _destroy(zcm_trans_t *zt)
    { delete cast(zt); }

    static const TransportRegister regUdpd;
};

zcm_trans_methods_t ZCM_TRANS_CLASSNAME::methods = {
    &ZCM_TRANS_CLASSNAME::_getMtu,
    &ZCM_TRANS_CLASSNAME::_sendmsg,
    &ZCM_TRANS_CLASSNAME::_recvmsgEnable,
    &ZCM_TRANS_CLASSNAME::_recvmsg,
    NULL, // update
    &ZCM_TRANS_CLASSNAME::_destroy,
};

static const char *optFind(zcm_url_opts_t *opts, const string& key)
{
    for (size_t i = 0; i < opts->numopts; i++)
        if (key == opts->name[i])
            return opts->value[i];
    return NULL;
}

// TODO: this probably belongs more in a string util like file
#include <sstream>
static vector<string> split(const string& str, char delimiter)
{
    vector<string> v;
    std::stringstream ss {str};
    string tok;

    while(getline(ss, tok, delimiter))
        v.push_back(std::move(tok));

    auto len = str.size();
    if (len > 0 && str[len-1] == delimiter)
        v.push_back("");

    return v;
}

static zcm_trans_t *createUdpd(zcm_url_t *url)
{

    auto *ip = zcm_url_address(url);
    vector<string> parts = split(ip, ':');
    if (parts.size() != 2) {
        ZCM_DEBUG("ERROR: Url format is <ip-address>:<port-num>");
        return nullptr;
    }

    auto& src_address = parts[0];
    auto& src_port = parts[1];
    UdpdAddress udpd_src_address(src_address, atoi(src_port.c_str()));


    auto *opts = zcm_url_opts(url);
    auto ttl = optFind(opts, "ttl");
    if (!ttl) {
        ZCM_DEBUG("No ttl specified. Using default ttl=0");
        ttl = "0";
    }

    auto *keep_alive = optFind(opts, "keep_alive");
    if (!keep_alive) {
        ZCM_DEBUG("No keep alive time specified. Working without destination pool cleaning");
        keep_alive = "0";
    }

    size_t recv_buf_size = 1024;

    UDPD::Params params(udpd_src_address, recv_buf_size, atoi(ttl), atoi(keep_alive));

    auto *trans = new ZCM_TRANS_CLASSNAME(params);
    if (!trans->init()) {
        delete trans;
        return nullptr;
    } else {
        return trans;
    }

}

#ifdef USING_TRANS_UDPD
// Register this transport with ZCM
const TransportRegister ZCM_TRANS_CLASSNAME::regUdpd(
    "udpd", "Transfer data via UDPD (e.g. 'udpd')", createUdpd);
#endif
