#pragma once

#include "platform.hpp"

#include <cstdint>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace llarp::vpn
{
  class Socks6PacketPlatform final : public Platform
  {
   public:
    Socks6PacketPlatform();
    ~Socks6PacketPlatform() override;

    int
    Enable();

    bool
    IsEnabled() const;

    int
    SendPacket(const byte_t* data, size_t size);

    int
    ReceivePacket(byte_t* data, size_t capacity, size_t* size, uint32_t timeout_ms);

    int
    GetLocalAddress(char* data, size_t capacity);

    IRouteManager&
    RouteManager() override;

   protected:
    std::shared_ptr<NetworkInterface>
    ObtainInterface(InterfaceInfo info, AbstractRouter* router) override;

   private:
    friend class Socks6PacketInterface;

    net::IPPacket
    ReadNextPacket();

    bool
    WritePacket(net::IPPacket packet);

    void
    Close();

    int m_PollFD = -1;
    bool m_Enabled = false;
    bool m_Closed = false;
    uint64_t m_DroppedPackets = 0;
    std::string m_LocalAddress;
    std::deque<std::vector<byte_t>> m_ToLokinet;
    std::deque<std::vector<byte_t>> m_ToClient;
    mutable std::mutex m_Access;
    std::condition_variable m_PacketReady;
    std::unique_ptr<IRouteManager> m_RouteManager;
  };
}  // namespace llarp::vpn
