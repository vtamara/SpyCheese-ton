/*
    This file is part of TON Blockchain Library.

    TON Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TON Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TON Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
*/
#include "adnl-tunnel.h"
#include "adnl/adnl-peer-table.h"

namespace ton {

namespace adnl {

void AdnlInboundTunnelEndpoint::receive_packet(AdnlNodeIdShort src, td::IPAddress src_addr, td::BufferSlice datagram) {
  for (size_t idx = 0; idx < decryptors_.size(); ++idx) {
    auto prefix = fetch_tl_prefix<ton_api::adnl_tunnel_packetPrefix>(datagram, true);
    if (prefix.is_error()) {
      VLOG(ADNL_INFO) << "dropping datagram with invalid prefix";
      return;
    }
    if (prefix.ok()->id_ != decryptors_[idx].second) {
      VLOG(ADNL_INFO) << "invalid tunnel midpoint";
      return;
    }
    auto R = decryptors_[idx].first->decrypt(std::move(datagram));
    if (R.is_error()) {
      VLOG(ADNL_INFO) << "dropping tunnel packet: failed to decrypt: " << R.move_as_error();
      return;
    }
    datagram = R.move_as_ok();
    if (idx == decryptors_.size() - 1) {
      break;
    }
    auto F = fetch_tl_object<ton_api::adnl_tunnel_packetContents>(datagram, true);
    if (F.is_error()) {
      auto F2 = fetch_tl_object<ton_api::adnl_tunnel_customMessage>(datagram, true);
      if (F2.is_ok()) {
        if (callback_) {
          callback_->receive_custom_message(idx, std::move(F2.ok()->data_));
        }
        return;
      }
      VLOG(ADNL_INFO) << "dropping tunnel packet: failed to fetch: " << F.move_as_error();
      return;
    }
    auto packet = F.move_as_ok();
    td::IPAddress addr;
    if (packet->flags_ & 1) {
      addr.init_host_port(td::IPAddress::ipv4_to_str(packet->from_ip_), packet->from_port_).ignore();
    }
    if (!(packet->flags_ & 2)) {
      return;
    }
    datagram = std::move(packet->message_);
  }
  AdnlCategoryMask cat_mask;
  cat_mask.set();
  td::actor::send_closure(adnl_, &Adnl::receive_packet, src_addr, cat_mask, std::move(datagram));
}

void AdnlInboundTunnelMidpoint::start_up() {
  encrypt_key_hash_ = encrypt_via_.compute_short_id();
  auto R = encrypt_via_.create_encryptor();
  if (R.is_error()) {
    return;
  }
  encryptor_ = R.move_as_ok();
}

void AdnlInboundTunnelMidpoint::receive_packet(AdnlNodeIdShort src, td::IPAddress src_addr, td::BufferSlice datagram) {
  if (!encryptor_) {
    return;
  }
  auto obj = create_tl_object<ton_api::adnl_tunnel_packetContents>();
  obj->flags_ = 2;
  obj->message_ = std::move(datagram);
  if (src_addr.is_valid() && src_addr.is_ipv4()) {
    obj->flags_ |= 1;
    obj->from_ip_ = src_addr.get_ipv4();
    obj->from_port_ = src_addr.get_port();
  }
  auto packet = serialize_tl_object(std::move(obj), true);
  auto dataR = encryptor_->encrypt(packet.as_slice());
  if (dataR.is_error()) {
    return;
  }
  auto data = dataR.move_as_ok();
  td::BufferSlice enc = create_serialize_tl_object_suffix<ton_api::adnl_tunnel_packetPrefix>(
      data.as_slice(), encrypt_key_hash_.bits256_value());

  td::actor::send_closure(adnl_, &Adnl::send_message_ex, proxy_as_, proxy_to_, std::move(enc),
                          Adnl::SendFlags::direct_only);
}

void AdnlInboundTunnelMidpoint::send_custom_message(td::BufferSlice data) {
  if (!encryptor_) {
    return;
  }
  data = create_serialize_tl_object<ton_api::adnl_tunnel_customMessage>(std::move(data));
  auto dataR = encryptor_->encrypt(data.as_slice());
  if (dataR.is_error()) {
    return;
  }
  data = dataR.move_as_ok();
  td::BufferSlice enc = create_serialize_tl_object_suffix<ton_api::adnl_tunnel_packetPrefix>(
      data.as_slice(), encrypt_key_hash_.bits256_value());
  td::actor::send_closure(adnl_, &Adnl::send_message_ex, proxy_as_, proxy_to_, std::move(enc),
                          Adnl::SendFlags::direct_only);
}

}  // namespace adnl
}  // namespace ton
