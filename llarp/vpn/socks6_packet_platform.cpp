#include "socks6_packet_platform.hpp"

#include <llarp/router/abstractrouter.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>

#ifdef __linux__
#include <sys/eventfd.h>
#include <unistd.h>
#endif

namespace llarp::vpn
{
  namespace
  {
    constexpr size_t MaxQueuedPackets = 256;

    class NoopRouteManager final : public IRouteManager
    {
     public:
      void
      AddRoute(net::ipaddr_t, net::ipaddr_t) override
      {}

      void
      DelRoute(net::ipaddr_t, net::ipaddr_t) override
      {}

      void
      AddDefaultRouteViaInterface(NetworkInterface&) override
      {}

      void
      DelDefaultRouteViaInterface(NetworkInterface&) override
      {}

      void
      AddRouteViaInterface(NetworkInterface&, IPRange) override
      {}

      void
      DelRouteViaInterface(NetworkInterface&, IPRange) override
      {}

      std::vector<net::ipaddr_t>
      GetGatewaysNotOnInterface(NetworkInterface&) override
      {
        return {};
      }
    };
  }  // namespace

  class Socks6PacketInterface final : public NetworkInterface
  {
   public:
    Socks6PacketInterface(
        InterfaceInfo info, Socks6PacketPlatform& platform, AbstractRouter* router)
        : NetworkInterface{std::move(info)}, m_Platform{platform}, m_Router{router}
    {}

    ~Socks6PacketInterface() override
    {
      Stop();
    }

    void
    Stop() override
    {
      if (not m_Stopped)
      {
        m_Stopped = true;
        m_Platform.Close();
      }
    }

    net::IPPacket
    ReadNextPacket() override
    {
      return m_Platform.ReadNextPacket();
    }

    bool
    WritePacket(net::IPPacket packet) override
    {
      return m_Platform.WritePacket(std::move(packet));
    }

    int
    PollFD() const override
    {
      return m_Platform.m_PollFD;
    }

    void
    MaybeWakeUpperLayers() const override
    {
      if (m_Router)
        m_Router->TriggerPump();
    }

   private:
    Socks6PacketPlatform& m_Platform;
    AbstractRouter* m_Router;
    bool m_Stopped = false;
  };

  Socks6PacketPlatform::Socks6PacketPlatform()
      : m_RouteManager{std::make_unique<NoopRouteManager>()}
  {}

  Socks6PacketPlatform::~Socks6PacketPlatform()
  {
#ifdef __linux__
    if (m_PollFD >= 0)
      close(m_PollFD);
#endif
  }

  int
  Socks6PacketPlatform::Enable()
  {
#ifdef __linux__
    std::unique_lock lock{m_Access};
    if (m_Enabled)
      return 0;
    m_PollFD = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (m_PollFD < 0)
      return errno;
    m_Enabled = true;
    return 0;
#else
    return ENOTSUP;
#endif
  }

  bool
  Socks6PacketPlatform::IsEnabled() const
  {
    std::unique_lock lock{m_Access};
    return m_Enabled;
  }

  std::shared_ptr<NetworkInterface>
  Socks6PacketPlatform::ObtainInterface(InterfaceInfo info, AbstractRouter* router)
  {
    std::unique_lock lock{m_Access};
    if (not m_Enabled or m_PollFD < 0)
      throw std::runtime_error{"SOCKS6 packet I/O is not enabled"};
    if (info.addrs.empty())
      throw std::runtime_error{"Lokinet did not configure a packet interface address"};
    info.index = 1;
    m_LocalAddress = net::ToString(info[0]);
    return std::make_shared<Socks6PacketInterface>(std::move(info), *this, router);
  }

  IRouteManager&
  Socks6PacketPlatform::RouteManager()
  {
    return *m_RouteManager;
  }

  int
  Socks6PacketPlatform::SendPacket(const byte_t* data, size_t size)
  {
    if (data == nullptr or size < net::IPPacket::MinSize)
      return EINVAL;
    if (size > net::IPPacket::MaxSize)
      return EMSGSIZE;

    std::unique_lock lock{m_Access};
    if (not m_Enabled or m_PollFD < 0)
      return ENOTCONN;
    if (m_Closed)
      return EPIPE;
    if (m_ToLokinet.size() >= MaxQueuedPackets)
      return ENOBUFS;

    m_ToLokinet.emplace_back(data, data + size);
#ifdef __linux__
    const uint64_t one = 1;
    if (write(m_PollFD, &one, sizeof(one)) < 0 and errno != EAGAIN)
    {
      m_ToLokinet.pop_back();
      return errno;
    }
#endif
    return 0;
  }

  int
  Socks6PacketPlatform::ReceivePacket(
      byte_t* data, size_t capacity, size_t* size, uint32_t timeout_ms)
  {
    if (data == nullptr or size == nullptr or capacity < net::IPPacket::MinSize)
      return EINVAL;

    std::unique_lock lock{m_Access};
    if (not m_Enabled)
      return ENOTCONN;
    const auto ready = [this] { return m_Closed or not m_ToClient.empty(); };
    if (not ready() and not m_PacketReady.wait_for(
                            lock, std::chrono::milliseconds{timeout_ms}, ready))
      return ETIMEDOUT;
    if (m_ToClient.empty())
      return EPIPE;

    const auto& packet = m_ToClient.front();
    if (packet.size() > capacity)
      return EMSGSIZE;
    std::memcpy(data, packet.data(), packet.size());
    *size = packet.size();
    m_ToClient.pop_front();
    return 0;
  }

  int
  Socks6PacketPlatform::GetLocalAddress(char* data, size_t capacity)
  {
    if (data == nullptr or capacity == 0)
      return EINVAL;
    std::unique_lock lock{m_Access};
    if (m_LocalAddress.empty())
      return EAGAIN;
    if (m_LocalAddress.size() >= capacity)
      return ENOSPC;
    std::memcpy(data, m_LocalAddress.c_str(), m_LocalAddress.size() + 1);
    return 0;
  }

  net::IPPacket
  Socks6PacketPlatform::ReadNextPacket()
  {
    std::unique_lock lock{m_Access};
    if (m_ToLokinet.empty())
    {
#ifdef __linux__
      uint64_t count;
      while (read(m_PollFD, &count, sizeof(count)) < 0 and errno == EINTR)
      {}
#endif
      return {};
    }

    auto packet = std::move(m_ToLokinet.front());
    m_ToLokinet.pop_front();
    if (m_ToLokinet.empty())
    {
#ifdef __linux__
      uint64_t count;
      while (read(m_PollFD, &count, sizeof(count)) < 0 and errno == EINTR)
      {}
#endif
    }
    return net::IPPacket{std::move(packet)};
  }

  bool
  Socks6PacketPlatform::WritePacket(net::IPPacket packet)
  {
    if (packet.size() < net::IPPacket::MinSize or packet.size() > net::IPPacket::MaxSize)
      return false;
    {
      std::unique_lock lock{m_Access};
      if (m_Closed or m_ToClient.size() >= MaxQueuedPackets)
      {
        ++m_DroppedPackets;
        return false;
      }
      m_ToClient.push_back(packet.steal());
    }
    m_PacketReady.notify_one();
    return true;
  }

  void
  Socks6PacketPlatform::Close()
  {
    {
      std::unique_lock lock{m_Access};
      m_Closed = true;
    }
    m_PacketReady.notify_all();
  }
}  // namespace llarp::vpn
