#include <lokinet.h>
#include <llarp.hpp>
#include <llarp/config/config.hpp>
#include <llarp/crypto/crypto_libsodium.hpp>

#include <llarp/router/abstractrouter.hpp>
#include <llarp/service/context.hpp>
#include <llarp/service/name.hpp>
#include <llarp/quic/tunnel.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/handlers/tun.hpp>
#include <llarp/vpn/socks6_packet_platform.hpp>

#include <llarp/util/logging.hpp>
#include <llarp/util/logging/buffer.hpp>
#include <llarp/util/logging/callback_sink.hpp>

#include <oxenc/base32z.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <condition_variable>
#include <future>
#include <mutex>
#include <memory>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <unordered_map>

#ifdef _WIN32
#define EHOSTDOWN ENETDOWN
#endif

namespace
{
  std::string
  lowercase_ascii(std::string value)
  {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
      return static_cast<char>(std::tolower(ch));
    });
    return value;
  }

  struct Context : public llarp::Context
  {
    explicit Context(std::shared_ptr<llarp::vpn::Socks6PacketPlatform> packet_platform)
        : m_PacketPlatform{std::move(packet_platform)}
    {}

    std::shared_ptr<llarp::NodeDB>
    makeNodeDB() override
    {
      return std::make_shared<llarp::NodeDB>();
    }

    std::shared_ptr<llarp::vpn::Platform>
    makeVPNPlatform() override
    {
      if (m_PacketPlatform->IsEnabled())
        return m_PacketPlatform;
      return llarp::Context::makeVPNPlatform();
    }

   private:
    std::shared_ptr<llarp::vpn::Socks6PacketPlatform> m_PacketPlatform;
  };

  struct UDPFlow
  {
    using Clock_t = std::chrono::steady_clock;
    void* m_FlowUserData;
    std::chrono::seconds m_FlowTimeout;
    std::chrono::time_point<Clock_t> m_ExpiresAt;
    lokinet_udp_flowinfo m_FlowInfo;
    lokinet_udp_flow_recv_func m_Recv;

    /// call timeout hook for this flow
    void
    TimedOut(lokinet_udp_flow_timeout_func timeout)
    {
      timeout(&m_FlowInfo, m_FlowUserData);
    }

    /// mark this flow as active
    /// updates the expires at timestamp
    void
    MarkActive()
    {
      m_ExpiresAt = Clock_t::now() + m_FlowTimeout;
    }

    /// returns true if we think this flow is expired
    bool
    IsExpired() const
    {
      return Clock_t::now() >= m_ExpiresAt;
    }

    void
    HandlePacket(const llarp::net::IPPacket& pkt)
    {
      if (auto maybe = pkt.L4Data())
      {
        MarkActive();
        m_Recv(&m_FlowInfo, maybe->first, maybe->second, m_FlowUserData);
      }
    }
  };

  struct UDPHandler
  {
    using AddressVariant_t = llarp::vpn::AddressVariant_t;
    int m_SocketID;
    llarp::nuint16_t m_LocalPort;
    lokinet_udp_flow_filter m_Filter;
    lokinet_udp_flow_recv_func m_Recv;
    lokinet_udp_flow_timeout_func m_Timeout;
    void* m_User;
    std::weak_ptr<llarp::service::Endpoint> m_Endpoint;

    std::unordered_map<AddressVariant_t, UDPFlow> m_Flows;
    std::unordered_map<std::string, AddressVariant_t> m_RemoteAddresses;

    std::mutex m_Access;

    explicit UDPHandler(
        int socketid,
        llarp::nuint16_t localport,
        lokinet_udp_flow_filter filter,
        lokinet_udp_flow_recv_func recv,
        lokinet_udp_flow_timeout_func timeout,
        void* user,
        std::weak_ptr<llarp::service::Endpoint> ep)
        : m_SocketID{socketid}
        , m_LocalPort{localport}
        , m_Filter{filter}
        , m_Recv{recv}
        , m_Timeout{timeout}
        , m_User{user}
        , m_Endpoint{std::move(ep)}
    {}

    void
    KillAllFlows()
    {
      std::unique_lock lock{m_Access};
      for (auto& item : m_Flows)
      {
        item.second.TimedOut(m_Timeout);
      }
      m_Flows.clear();
      m_RemoteAddresses.clear();
    }

    bool
    AddFlow(
        const AddressVariant_t& from,
        const lokinet_udp_flowinfo& flow_addr,
        void* flow_userdata,
        int flow_timeoutseconds,
        std::optional<llarp::net::IPPacket> firstPacket = std::nullopt,
        bool rejectDuplicate = false)
    {
      std::unique_lock lock{m_Access};
      auto [itr, inserted] = m_Flows.try_emplace(from);
      if (rejectDuplicate and not inserted)
        return false;
      auto& flow = itr->second;
      flow.m_FlowInfo = flow_addr;
      flow.m_FlowTimeout = std::chrono::seconds{flow_timeoutseconds};
      flow.m_FlowUserData = flow_userdata;
      flow.m_Recv = m_Recv;
      if (firstPacket)
        flow.HandlePacket(*firstPacket);
      return true;
    }

    void
    ExpireOldFlows()
    {
      std::unique_lock lock{m_Access};
      for (auto itr = m_Flows.begin(); itr != m_Flows.end();)
      {
        if (itr->second.IsExpired())
        {
          itr->second.TimedOut(m_Timeout);
          m_RemoteAddresses.erase(lowercase_ascii(itr->second.m_FlowInfo.remote_host));
          itr = m_Flows.erase(itr);
        }
        else
          ++itr;
      }
    }

    void
    HandlePacketFrom(AddressVariant_t from, llarp::net::IPPacket pkt)
    {
      {
        std::unique_lock lock{m_Access};
        if (m_Flows.count(from))
        {
          m_Flows[from].HandlePacket(pkt);
          return;
        }
      }
      lokinet_udp_flowinfo flow_addr{};
      // set flow remote address
      std::string addrstr = var::visit([](auto&& from) { return from.ToString(); }, from);

      std::copy_n(
          addrstr.data(),
          std::min(addrstr.size(), sizeof(flow_addr.remote_host)),
          flow_addr.remote_host);
      // set socket id
      flow_addr.socket_id = m_SocketID;
      // get source port
      if (const auto srcport = pkt.SrcPort())
      {
        flow_addr.remote_port = ToHost(*srcport).h;
      }
      else
        return;  // invalid data so we bail
      void* flow_userdata = nullptr;
      int flow_timeoutseconds{};
      // got a new flow, let's check if we want it
      if (m_Filter(m_User, &flow_addr, &flow_userdata, &flow_timeoutseconds))
        return;
      AddFlow(from, flow_addr, flow_userdata, flow_timeoutseconds, pkt);
    }
  };
}  // namespace

struct lokinet_stream_open_status
{
  std::mutex mutex;
  std::condition_variable changed;
  std::optional<llarp::quic::TunnelManager::OpenResult> result;

  void
  complete(llarp::quic::TunnelManager::OpenResult value)
  {
    {
      std::unique_lock lock{mutex};
      if (result)
        return;
      result = std::move(value);
    }
    changed.notify_all();
  }
};

struct lokinet_context
{
  std::mutex m_access;

  std::shared_ptr<llarp::vpn::Socks6PacketPlatform> packet_platform =
      std::make_shared<llarp::vpn::Socks6PacketPlatform>();
  std::shared_ptr<llarp::Context> impl = std::make_shared<Context>(packet_platform);
  std::shared_ptr<llarp::Config> config = llarp::Config::EmbeddedConfig();
  bool config_set = false;

  std::unique_ptr<std::thread> runner;

  int _socket_id = 0;

  ~lokinet_context()
  {
    if (runner)
      runner->join();
  }

  int
  next_socket_id()
  {
    int id = ++_socket_id;
    // handle overflow
    if (id < 0)
    {
      _socket_id = 0;
      id = ++_socket_id;
    }
    return id;
  }

  /// make a udp handler and hold onto it
  /// return its id
  [[nodiscard]] std::optional<int>
  make_udp_handler(
      const std::shared_ptr<llarp::service::Endpoint>& ep,
      llarp::net::port_t exposePort,
      lokinet_udp_flow_filter filter,
      lokinet_udp_flow_recv_func recv,
      lokinet_udp_flow_timeout_func timeout,
      void* user)
  {
    if (udp_sockets.empty())
    {
      // start udp flow expiration timer
      impl->router->loop()->call_every(1s, std::make_shared<int>(0), [this]() {
        std::unique_lock lock{m_access};
        for (auto& item : udp_sockets)
        {
          item.second->ExpireOldFlows();
        }
      });
    }
    std::weak_ptr<llarp::service::Endpoint> weak{ep};
    auto udp = std::make_shared<UDPHandler>(
        next_socket_id(), exposePort, filter, recv, timeout, user, weak);
    auto id = udp->m_SocketID;
    std::promise<bool> result;

    impl->router->loop()->call([ep, &result, udp, exposePort]() {
      if (auto pkt = ep->EgresPacketRouter())
      {
        result.set_value(pkt->AddUDPHandler(
            llarp::net::ToHost(exposePort), [udp](auto from, auto pkt) {
              udp->HandlePacketFrom(std::move(from), std::move(pkt));
            }));
      }
      else
        result.set_value(false);
    });

    if (result.get_future().get())
    {
      udp_sockets[udp->m_SocketID] = std::move(udp);
      return id;
    }
    return std::nullopt;
  }

  void
  remove_udp_handler(int socket_id)
  {
    std::shared_ptr<UDPHandler> udp;
    {
      std::unique_lock lock{m_access};
      if (auto itr = udp_sockets.find(socket_id); itr != udp_sockets.end())
      {
        udp = std::move(itr->second);
        udp_sockets.erase(itr);
      }
    }
    if (udp)
    {
      auto remove = [udp]() {
        udp->KillAllFlows();
        if (auto ep = udp->m_Endpoint.lock())
        {
          if (auto pkt = ep->EgresPacketRouter())
            pkt->RemoveUDPHandler(llarp::ToHost(udp->m_LocalPort));
        }
      };
      auto loop = impl->router->loop();
      if (loop->inEventLoop())
        remove();
      else
      {
        std::promise<void> removed;
        loop->call([remove = std::move(remove), &removed]() mutable {
          remove();
          removed.set_value();
        });
        removed.get_future().wait();
      }
    }
  }

  /// acquire mutex for accessing this context
  [[nodiscard]] auto
  acquire()
  {
    return std::unique_lock{m_access};
  }

  [[nodiscard]] auto
  endpoint(std::string name = "default") const
  {
    return impl->router->hiddenServiceContext().GetEndpointByName(name);
  }

  std::unordered_map<int, bool> streams;
  std::unordered_map<int, std::shared_ptr<lokinet_stream_open_status>> stream_open_status;
  std::unordered_map<int, std::shared_ptr<UDPHandler>> udp_sockets;

  void
  inbound_stream(int id)
  {
    streams[id] = true;
  }

  void
  outbound_stream(int id, std::shared_ptr<lokinet_stream_open_status> status)
  {
    streams[id] = false;
    stream_open_status[id] = std::move(status);
  }
};

namespace
{
  void
  stream_error(lokinet_stream_result* result, int err)
  {
    std::memset(result, 0, sizeof(lokinet_stream_result));
    result->error = err;
  }

  void
  stream_okay(lokinet_stream_result* result, std::string host, int port, int stream_id)
  {
    stream_error(result, 0);
    std::copy_n(
        host.c_str(),
        std::min(host.size(), sizeof(result->local_address) - 1),
        result->local_address);
    result->local_port = port;
    result->stream_id = stream_id;
  }

  std::pair<std::string, int>
  split_host_port(std::string data, std::string proto = "tcp")
  {
    std::string host, portStr;
    if (auto pos = data.find(":"); pos != std::string::npos)
    {
      host = data.substr(0, pos);
      portStr = data.substr(pos + 1);
    }
    else
      throw EINVAL;

    if (auto* serv = getservbyname(portStr.c_str(), proto.c_str()))
    {
      return {host, serv->s_port};
    }
    return {host, std::stoi(portStr)};
  }

  int
  accept_port(const char* remote, uint16_t port, void* ptr)
  {
    (void)remote;
    if (port == *static_cast<uint16_t*>(ptr))
    {
      return 0;
    }
    return -1;
  }

  std::optional<lokinet_srv_record>
  SRVFromData(const llarp::dns::SRVData& data, std::string name)
  {
    // TODO: implement me
    (void)data;
    (void)name;
    return std::nullopt;
  }

}  // namespace

struct lokinet_srv_lookup_private
{
  std::vector<lokinet_srv_record> results;

  int
  LookupSRV(std::string host, std::string service, lokinet_context* ctx)
  {
    std::promise<int> promise;
    {
      auto lock = ctx->acquire();
      if (ctx->impl and ctx->impl->IsUp())
      {
        ctx->impl->CallSafe([host, service, &promise, ctx, this]() {
          auto ep = ctx->endpoint();
          if (ep == nullptr)
          {
            promise.set_value(ENOTSUP);
            return;
          }
          ep->LookupServiceAsync(host, service, [this, &promise, host](auto results) {
            for (const auto& result : results)
            {
              if (auto maybe = SRVFromData(result, host))
                this->results.emplace_back(*maybe);
            }
            promise.set_value(0);
          });
        });
      }
      else
      {
        promise.set_value(EHOSTDOWN);
      }
    }
    auto future = promise.get_future();
    return future.get();
  }

  void
  IterateAll(std::function<void(lokinet_srv_record*)> visit)
  {
    for (auto& result : results)
      visit(&result);
    // null terminator
    visit(nullptr);
  }
};

extern "C"
{
  void EXPORT
  lokinet_set_netid(const char* netid)
  {
    llarp::NetID::DefaultValue() = llarp::NetID{reinterpret_cast<const byte_t*>(netid)};
  }

  const char* EXPORT
  lokinet_get_netid()
  {
    const auto netid = llarp::NetID::DefaultValue().ToString();
    return strdup(netid.c_str());
  }

  static auto last_log_set = llarp::log::Level::info;

  int EXPORT
  lokinet_log_level(const char* level)
  {
    try
    {
      auto new_level = llarp::log::level_from_string(level);
      llarp::log::reset_level(new_level);
      last_log_set = new_level;
      return 0;
    }
    catch (std::invalid_argument& e)
    {
      llarp::LogError(e.what());
    }
    return -1;
  }

  char* EXPORT
  lokinet_address(struct lokinet_context* ctx)
  {
    if (not ctx)
      return nullptr;
    auto lock = ctx->acquire();
    auto ep = ctx->endpoint();
    const auto addr = ep->GetIdentity().pub.Addr();
    const auto addrStr = addr.ToString();
    return strdup(addrStr.c_str());
  }

  int EXPORT
  lokinet_add_bootstrap_rc(const char* data, size_t datalen, struct lokinet_context* ctx)
  {
    if (data == nullptr or datalen == 0)
      return -3;
    llarp_buffer_t buf{data, datalen};
    if (ctx == nullptr)
      return -3;
    auto lock = ctx->acquire();
    // add a temp cryptography implementation here so rc.Verify works
    llarp::CryptoManager instance{new llarp::sodium::CryptoLibSodium{}};
    if (data[0] == 'l')
    {
      if (not ctx->config->bootstrap.routers.BDecode(&buf))
      {
        llarp::LogError("Cannot decode bootstrap list: ", llarp::buffer_printer{buf});
        return -1;
      }
      for (const auto& rc : ctx->config->bootstrap.routers)
      {
        if (not rc.Verify(llarp::time_now_ms()))
          return -2;
      }
    }
    else
    {
      llarp::RouterContact rc{};
      if (not rc.BDecode(&buf))
      {
        llarp::LogError("failed to decode signle RC: ", llarp::buffer_printer{buf});
        return -1;
      }
      if (not rc.Verify(llarp::time_now_ms()))
        return -2;
      ctx->config->bootstrap.routers.insert(std::move(rc));
    }
    return 0;
  }

  struct lokinet_context* EXPORT
  lokinet_context_new()
  {
    return new lokinet_context{};
  }

  int EXPORT
  lokinet_context_set_config(
      const char* config_text,
      const char* data_dir,
      char* error_buffer,
      size_t error_buffer_size,
      struct lokinet_context* ctx)
  {
    auto fail = [error_buffer, error_buffer_size](int error, const char* message) {
      if (error_buffer && error_buffer_size)
        std::snprintf(error_buffer, error_buffer_size, "%s", message);
      return error;
    };

    if (!ctx || !config_text || !data_dir)
      return fail(EINVAL, "config text, data directory, and context are required");

    auto lock = ctx->acquire();
    if (ctx->runner)
      return fail(EBUSY, "Lokinet context has already been started");
    if (ctx->packet_platform->IsEnabled())
      return fail(EBUSY, "packet I/O has already been enabled");

    try
    {
      const std::filesystem::path data_path{data_dir};
      if (!data_path.is_absolute())
        return fail(EINVAL, "Lokinet data directory must be absolute");

      auto config = llarp::Config::EmbeddedConfig(data_path);
      if (!config->LoadString(config_text))
        return fail(EINVAL, "failed to parse Lokinet configuration");

      config->logging.m_logLevel = llarp::log::Level::off;
      config->api.m_enableRPCServer = false;
      config->network.m_endpointType = "null";
      config->network.m_saveProfiles = false;
      config->bootstrap.files.clear();
      ctx->config = std::move(config);
      ctx->config_set = true;
      if (error_buffer && error_buffer_size)
        error_buffer[0] = '\0';
      return 0;
    }
    catch (const std::exception& e)
    {
      return fail(EINVAL, e.what());
    }
  }

  int EXPORT
  lokinet_context_enable_ip_packet_io(struct lokinet_context* ctx)
  {
    if (not ctx)
      return EINVAL;
    auto lock = ctx->acquire();
    if (ctx->runner)
      return EBUSY;
    if (not ctx->config_set)
      return EINVAL;
    const int result = ctx->packet_platform->Enable();
    if (result != 0)
      return result;
    ctx->config->network.m_endpointType = "tun";
    ctx->config->dns.m_bind.clear();
    ctx->config->network.m_EnableRoutePoker = false;
    return 0;
  }

  int EXPORT
  lokinet_ip_packet_send(
      const uint8_t* packet, size_t packet_size, struct lokinet_context* ctx)
  {
    if (not ctx)
      return EINVAL;
    return ctx->packet_platform->SendPacket(packet, packet_size);
  }

  int EXPORT
  lokinet_ip_packet_receive(
      uint8_t* packet,
      size_t packet_capacity,
      size_t* packet_size,
      uint32_t timeout_ms,
      struct lokinet_context* ctx)
  {
    if (not ctx)
      return EINVAL;
    return ctx->packet_platform->ReceivePacket(packet, packet_capacity, packet_size, timeout_ms);
  }

  int EXPORT
  lokinet_ip_packet_local_address(
      char* address, size_t address_capacity, struct lokinet_context* ctx)
  {
    if (not ctx)
      return EINVAL;
    return ctx->packet_platform->GetLocalAddress(address, address_capacity);
  }

  int EXPORT
  lokinet_ip_packet_local_ipv6_address(
      char* address, size_t address_capacity, struct lokinet_context* ctx)
  {
    if (not ctx or not address or address_capacity == 0)
      return EINVAL;
    auto lock = ctx->acquire();
    auto router = ctx->impl->router;
    if (not router)
      return EAGAIN;
    auto endpoint = std::dynamic_pointer_cast<llarp::handlers::TunEndpoint>(
        router->hiddenServiceContext().GetDefault());
    if (not endpoint)
      return EAGAIN;
    const auto value = endpoint->GetIfIPv6Addr().ToString();
    if (value.size() >= address_capacity)
      return ENOSPC;
    std::memcpy(address, value.c_str(), value.size() + 1);
    return 0;
  }

  void EXPORT
  lokinet_context_free(struct lokinet_context* ctx)
  {
    lokinet_context_stop(ctx);
    delete ctx;
  }

  int EXPORT
  lokinet_context_start(struct lokinet_context* ctx)
  {
    if (not ctx)
      return -1;
    auto lock = ctx->acquire();
    ctx->config->router.m_netId = lokinet_get_netid();
    ctx->config->logging.m_logLevel = last_log_set;
    ctx->runner = std::make_unique<std::thread>([ctx]() {
      llarp::util::SetThreadName("llarp-mainloop");
      ctx->impl->Configure(ctx->config);
      const llarp::RuntimeOptions opts{};
      try
      {
        ctx->impl->Setup(opts);
#ifdef SIG_PIPE
        signal(SIG_PIPE, SIGIGN);
#endif
        ctx->impl->Run(opts);
      }
      catch (std::exception& ex)
      {
        std::cerr << ex.what() << std::endl;
        ctx->impl->CloseAsync();
      }
    });
    while (not ctx->impl->IsUp())
    {
      if (ctx->impl->IsStopping())
        return -1;
      std::this_thread::sleep_for(50ms);
    }
    return 0;
  }

  int EXPORT
  lokinet_status(struct lokinet_context* ctx)
  {
    if (ctx == nullptr)
      return -3;
    auto lock = ctx->acquire();
    if (not ctx->impl->IsUp())
      return -3;
    if (not ctx->impl->LooksAlive())
      return -2;
    return ctx->endpoint()->IsReady() ? 0 : -1;
  }

  int EXPORT
  lokinet_wait_for_ready(int ms, struct lokinet_context* ctx)
  {
    if (ctx == nullptr)
      return -1;
    auto lock = ctx->acquire();
    auto ep = ctx->endpoint();
    int iterations = ms / 10;
    if (iterations <= 0)
    {
      ms = 10;
      iterations = 1;
    }
    while (not ep->IsReady() and iterations > 0)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{ms / 10});
      iterations--;
    }
    return ep->IsReady() ? 0 : -1;
  }

  void EXPORT
  lokinet_context_stop(struct lokinet_context* ctx)
  {
    if (not ctx)
      return;
    std::shared_ptr<llarp::Context> impl;
    std::unique_ptr<std::thread> runner;
    {
      auto lock = ctx->acquire();
      if (not ctx->runner)
        return;
      if (not ctx->impl->IsStopping())
        ctx->impl->CloseAsync();
      impl = ctx->impl;
      runner = std::move(ctx->runner);
    }
    impl->Wait();
    if (runner->joinable())
      runner->join();
  }

  void EXPORT
  lokinet_outbound_stream(
      struct lokinet_stream_result* result,
      const char* remote,
      const char* local,
      struct lokinet_context* ctx)
  {
    if (ctx == nullptr)
    {
      stream_error(result, EHOSTDOWN);
      return;
    }
    std::promise<void> promise;

    {
      auto lock = ctx->acquire();

      if (not ctx->impl->IsUp())
      {
        stream_error(result, EHOSTDOWN);
        return;
      }
      std::string remotehost;
      int remoteport;
      try
      {
        auto [h, p] = split_host_port(remote);
        remotehost = h;
        remoteport = p;
      }
      catch (int err)
      {
        stream_error(result, err);
        return;
      }
      // TODO: make configurable (?)
      std::string endpoint{"default"};

      llarp::SockAddr localAddr;
      try
      {
        if (local)
          localAddr = llarp::SockAddr{std::string{local}};
        else
          localAddr = llarp::SockAddr{"127.0.0.1:0"};
      }
      catch (std::exception& ex)
      {
        stream_error(result, EINVAL);
        return;
      }
      auto call = [&promise,
                   ctx,
                   result,
                   open_status = std::make_shared<lokinet_stream_open_status>(),
                   router = ctx->impl->router,
                   remotehost,
                   remoteport,
                   endpoint,
                   localAddr]() {
        auto ep = ctx->endpoint();
        if (ep == nullptr)
        {
          stream_error(result, ENOTSUP);
          promise.set_value();
          return;
        }
        auto* quic = ep->GetQUICTunnel();
        if (quic == nullptr)
        {
          stream_error(result, ENOTSUP);
          promise.set_value();
          return;
        }
        try
        {
          auto [addr, id] = quic->open(
              remotehost,
              remoteport,
              [open_status](auto open_result) { open_status->complete(std::move(open_result)); },
              localAddr);
          auto [host, port] = split_host_port(addr.ToString());
          ctx->outbound_stream(id, std::move(open_status));
          stream_okay(result, host, port, id);
        }
        catch (std::exception& ex)
        {
          std::cout << ex.what() << std::endl;
          stream_error(result, ECANCELED);
        }
        catch (int err)
        {
          stream_error(result, err);
        }
        promise.set_value();
      };

      ctx->impl->CallSafe([call]() {
        // we dont want the mainloop to die in case setting the value on the promise fails
        try
        {
          call();
        }
        catch (...)
        {}
      });
    }

    auto future = promise.get_future();
    try
    {
      if (auto status = future.wait_for(std::chrono::seconds{10});
          status == std::future_status::ready)
      {
        future.get();
      }
      else
      {
        stream_error(result, ETIMEDOUT);
      }
    }
    catch (std::exception& ex)
    {
      stream_error(result, EBADF);
    }
  }

  int EXPORT
  lokinet_stream_wait_ready(
      int stream_id,
      uint32_t timeout_ms,
      int* retryable,
      char* phase,
      size_t phase_capacity,
      struct lokinet_context* ctx)
  {
    if (ctx == nullptr || retryable == nullptr || (phase == nullptr && phase_capacity != 0))
      return EINVAL;
    std::shared_ptr<lokinet_stream_open_status> status;
    {
      auto lock = ctx->acquire();
      auto it = ctx->stream_open_status.find(stream_id);
      if (it == ctx->stream_open_status.end())
        return ENOENT;
      status = it->second;
    }

    std::unique_lock lock{status->mutex};
    if (!status->changed.wait_for(
            lock,
            std::chrono::milliseconds{timeout_ms},
            [&status] { return status->result.has_value(); }))
      return ETIMEDOUT;

    const auto& result = *status->result;
    *retryable = result.retryable ? 1 : 0;
    if (phase_capacity > 0)
    {
      const auto size = std::min(result.phase.size(), phase_capacity - 1);
      std::memcpy(phase, result.phase.data(), size);
      phase[size] = '\0';
    }
    return result.success ? 0 : EHOSTUNREACH;
  }

  int EXPORT
  lokinet_inbound_stream(uint16_t port, struct lokinet_context* ctx)
  {
    /// FIXME: delete pointer later
    return lokinet_inbound_stream_filter(&accept_port, (void*)new std::uintptr_t{port}, ctx);
  }

  int EXPORT
  lokinet_inbound_stream_filter(
      lokinet_stream_filter acceptFilter, void* user, struct lokinet_context* ctx)
  {
    if (acceptFilter == nullptr)
    {
      acceptFilter = [](auto, auto, auto) { return 0; };
    }
    if (not ctx)
      return -1;
    std::promise<int> promise;
    {
      auto lock = ctx->acquire();
      if (not ctx->impl->IsUp())
      {
        return -1;
      }

      ctx->impl->CallSafe([ctx, acceptFilter, user, &promise]() {
        auto ep = ctx->endpoint();
        auto* quic = ep->GetQUICTunnel();
        auto id = quic->listen(
            [acceptFilter, user](auto remoteAddr, auto port) -> std::optional<llarp::SockAddr> {
              std::string remote{remoteAddr};
              if (auto result = acceptFilter(remote.c_str(), port, user))
              {
                if (result == -1)
                {
                  throw std::invalid_argument{"rejected"};
                }
              }
              else
                return llarp::SockAddr{"127.0.0.1:" + std::to_string(port)};
              return std::nullopt;
            });
        promise.set_value(id);
      });
    }
    auto ftr = promise.get_future();
    auto id = ftr.get();
    {
      auto lock = ctx->acquire();
      ctx->inbound_stream(id);
    }
    return id;
  }

  char* EXPORT
  lokinet_hex_to_base32z(const char* hex)
  {
    std::string_view hexview{hex};
    if (not oxenc::is_hex(hexview))
      return nullptr;

    const size_t b32z_len = oxenc::to_base32z_size(oxenc::from_hex_size(hexview.size()));
    auto buf = std::make_unique<char[]>(b32z_len + 1);
    buf[b32z_len] = '\0';  // null terminate

    oxenc::hex_decoder decode{hexview.begin(), hexview.end()};
    oxenc::base32z_encoder encode{decode, decode.end()};
    std::copy(encode, encode.end(), buf.get());
    return buf.release();  // leak the buffer to the caller
  }

  void EXPORT
  lokinet_close_stream(int stream_id, struct lokinet_context* ctx)
  {
    if (not ctx)
      return;
    auto lock = ctx->acquire();
    auto stream = ctx->streams.find(stream_id);
    if (stream == ctx->streams.end())
      return;
    const bool inbound = stream->second;
    ctx->streams.erase(stream);
    if (auto it = ctx->stream_open_status.find(stream_id); it != ctx->stream_open_status.end())
    {
      it->second->complete({false, true, "cancelled"});
      ctx->stream_open_status.erase(it);
    }
    if (not ctx->impl->IsUp())
      return;

    try
    {
      std::promise<void> promise;
      ctx->impl->CallSafe([stream_id, inbound, ctx, &promise]() {
        auto ep = ctx->endpoint();
        auto* quic = ep->GetQUICTunnel();
        try
        {
          if (inbound)
            quic->forget(stream_id);
          else
            quic->close(stream_id);
        }
        catch (...)
        {}
        promise.set_value();
      });
      promise.get_future().get();
    }
    catch (...)
    {}
  }

  int EXPORT
  lokinet_srv_lookup(
      char* host,
      char* service,
      struct lokinet_srv_lookup_result* result,
      struct lokinet_context* ctx)
  {
    if (result == nullptr or ctx == nullptr or host == nullptr or service == nullptr)
      return -1;
    // sanity check, if the caller has not free()'d internals yet free them
    if (result->internal)
      delete result->internal;
    result->internal = new lokinet_srv_lookup_private{};
    return result->internal->LookupSRV(host, service, ctx);
  }

  void EXPORT
  lokinet_for_each_srv_record(
      struct lokinet_srv_lookup_result* result, lokinet_srv_record_iterator iter, void* user)
  {
    if (result and result->internal)
    {
      result->internal->IterateAll([iter, user](auto* result) { iter(result, user); });
    }
    else
    {
      iter(nullptr, user);
    }
  }

  void EXPORT
  lokinet_srv_lookup_done(struct lokinet_srv_lookup_result* result)
  {
    if (result == nullptr or result->internal == nullptr)
      return;
    delete result->internal;
    result->internal = nullptr;
  }

  int EXPORT
  lokinet_udp_bind(
      uint16_t exposedPort,
      lokinet_udp_flow_filter filter,
      lokinet_udp_flow_recv_func recv,
      lokinet_udp_flow_timeout_func timeout,
      void* user,
      struct lokinet_udp_bind_result* result,
      struct lokinet_context* ctx)
  {
    if (filter == nullptr or recv == nullptr or timeout == nullptr or result == nullptr
        or ctx == nullptr)
      return EINVAL;

    auto lock = ctx->acquire();
    if (auto ep = ctx->endpoint())
    {
      if (auto maybe = ctx->make_udp_handler(
              ep, llarp::net::port_t::from_host(exposedPort), filter, recv, timeout, user))
      {
        result->socket_id = *maybe;
        return 0;
      }
    }
    return EINVAL;
  }

  void EXPORT
  lokinet_udp_close(int socket_id, struct lokinet_context* ctx)
  {
    if (ctx)
    {
      ctx->remove_udp_handler(socket_id);
    }
  }

  int EXPORT
  lokinet_udp_flow_send(
      const struct lokinet_udp_flowinfo* remote,
      const void* ptr,
      size_t len,
      struct lokinet_context* ctx)
  {
    if (remote == nullptr or remote->remote_port == 0 or ptr == nullptr or ctx == nullptr)
      return EINVAL;
    std::shared_ptr<llarp::EndpointBase> ep;
    llarp::nuint16_t srcport{0};
    auto remote_host = lowercase_ascii(remote->remote_host);
    auto dstport = llarp::net::port_t::from_host(remote->remote_port);
    std::optional<llarp::EndpointBase::AddressVariant_t> remote_address;
    {
      auto lock = ctx->acquire();
      if (auto itr = ctx->udp_sockets.find(remote->socket_id); itr != ctx->udp_sockets.end())
      {
        ep = itr->second->m_Endpoint.lock();
        srcport = itr->second->m_LocalPort;
        if (auto parsed = llarp::service::ParseAddress(remote_host))
          remote_address = *parsed;
        else if (auto resolved = itr->second->m_RemoteAddresses.find(remote_host);
                 resolved != itr->second->m_RemoteAddresses.end())
          remote_address = resolved->second;
      }
      else
        return EHOSTUNREACH;
    }
    if (remote_address)
    {
      llarp::net::IPPacket pkt = llarp::net::IPPacket::UDP(
          llarp::nuint32_t{0},
          srcport,
          llarp::nuint32_t{0},
          dstport,
          llarp_buffer_t{reinterpret_cast<const uint8_t*>(ptr), len});

      if (pkt.empty())
        return EINVAL;
      std::promise<int> ret;
      ctx->impl->router->loop()->call(
          [addr = *remote_address, pkt = std::move(pkt), ep, &ret]() {
        if (auto tag = ep->GetBestConvoTagFor(addr))
        {
          if (ep->SendToOrQueue(*tag, pkt.ConstBuffer(), llarp::service::ProtocolType::TrafficV4))
          {
            ret.set_value(0);
            return;
          }
        }
        ret.set_value(ENETUNREACH);
      });
      return ret.get_future().get();
    }
    return EINVAL;
  }

  int EXPORT
  lokinet_udp_establish(
      lokinet_udp_create_flow_func create_flow,
      void* user,
      const struct lokinet_udp_flowinfo* remote,
      struct lokinet_context* ctx)
  {
    if (create_flow == nullptr or remote == nullptr or ctx == nullptr)
      return EINVAL;
    std::shared_ptr<llarp::EndpointBase> ep;
    {
      auto lock = ctx->acquire();
      if (ctx->impl->router->loop()->inEventLoop())
      {
        llarp::LogError("cannot call udp_establish from internal event loop");
        return EINVAL;
      }
      if (auto itr = ctx->udp_sockets.find(remote->socket_id); itr != ctx->udp_sockets.end())
      {
        ep = itr->second->m_Endpoint.lock();
      }
      else
        return EHOSTUNREACH;
    }
    const auto remote_host = lowercase_ascii(remote->remote_host);
    auto address = llarp::service::ParseAddress(remote_host);
    if (not address and llarp::service::NameIsValid(remote_host))
    {
      using AddressVariant = llarp::EndpointBase::AddressVariant_t;
      auto lookup = std::make_shared<std::promise<std::optional<AddressVariant>>>();
      auto lookup_result = lookup->get_future();
      ctx->impl->router->loop()->call([ep, remote_host, lookup]() {
        ep->LookupNameAsync(remote_host, [lookup](auto result) {
          lookup->set_value(std::move(result));
        });
      });
      if (lookup_result.wait_for(30s) != std::future_status::ready)
        return ETIMEDOUT;
      address = lookup_result.get();
    }

    if (not address)
      return EINVAL;

    using AddressVariant = llarp::EndpointBase::AddressVariant_t;
    const AddressVariant remote_address = *address;
    auto path_ready = std::make_shared<std::promise<bool>>();
    auto path_completed = std::make_shared<std::atomic_bool>(false);
    auto complete_path = [path_ready, path_completed](bool success) {
      if (not path_completed->exchange(true))
        path_ready->set_value(success);
    };
    auto path_result = path_ready->get_future();
    ctx->impl->router->loop()->call([ep, remote_address, complete_path]() {
      ep->MarkAddressOutbound(remote_address);
      auto started = ep->EnsurePathTo(
          remote_address,
          [complete_path](auto result) { complete_path(result.has_value()); },
          5s);
      if (not started)
        complete_path(false);
    });
    if (path_result.wait_for(7s) != std::future_status::ready or not path_result.get())
      return ETIMEDOUT;

    void* flow_data{nullptr};
    int flow_timeoutseconds{};
    create_flow(user, &flow_data, &flow_timeoutseconds);
    {
      auto lock = ctx->acquire();
      if (auto itr = ctx->udp_sockets.find(remote->socket_id); itr != ctx->udp_sockets.end())
      {
        auto& udp = itr->second;
        if (udp->m_RemoteAddresses.count(remote_host))
          return EADDRINUSE;
        if (not udp->AddFlow(remote_address, *remote, flow_data, flow_timeoutseconds, std::nullopt, true))
          return EADDRINUSE;
        udp->m_RemoteAddresses.emplace(remote_host, remote_address);
        return 0;
      }
    }
    return EHOSTUNREACH;
  }

  void EXPORT
  lokinet_set_syncing_logger(lokinet_logger_func func, lokinet_logger_sync sync, void* user)
  {
    llarp::log::clear_sinks();
    llarp::log::add_sink(std::make_shared<llarp::logging::CallbackSink_mt>(func, sync, user));
  }

  void EXPORT
  lokinet_set_logger(lokinet_logger_func func, void* user)
  {
    lokinet_set_syncing_logger(func, nullptr, user);
  }
}
