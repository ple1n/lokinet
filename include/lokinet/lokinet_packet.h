#pragma once

#include "lokinet_export.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  struct lokinet_context;

  /// Opt into Lokinet's existing packet-routing endpoint without opening a TUN device.
  /// Must be called after setting the config and before starting the context.
  int EXPORT
  lokinet_context_enable_ip_packet_io(struct lokinet_context*);

  /// Send one complete IP packet into Lokinet. Returns zero or an errno value.
  int EXPORT
  lokinet_ip_packet_send(
      const uint8_t* packet, size_t packet_size, struct lokinet_context*);

  /// Wait for one complete IP packet from Lokinet. Returns zero or an errno value.
  int EXPORT
  lokinet_ip_packet_receive(
      uint8_t* packet,
      size_t packet_capacity,
      size_t* packet_size,
      uint32_t timeout_ms,
      struct lokinet_context*);

  /// Copy the packet interface's source address into the caller's buffer.
  int EXPORT
  lokinet_ip_packet_local_address(char* address, size_t address_capacity, struct lokinet_context*);

  /// Copy the packet interface's IPv6 source address into the caller's buffer.
  int EXPORT
  lokinet_ip_packet_local_ipv6_address(
      char* address, size_t address_capacity, struct lokinet_context*);

#ifdef __cplusplus
}
#endif
