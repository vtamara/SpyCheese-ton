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
*/
#include "adnl-hop.hpp"
#include "auto/tl/ton_api.hpp"
#include "td/utils/overloaded.h"

namespace ton {

namespace adnl {

static const std::vector<std::string> PREFIXES = {
    Adnl::int_to_bytestring(ton_api::adnl_hop_forwardToUdp::ID),
    Adnl::int_to_bytestring(ton_api::adnl_hop_forwardToHop::ID),
    Adnl::int_to_bytestring(ton_api::adnl_hop_encryptedMessage::ID)
};

void AdnlHopServer::start_up() {
  class Callback : public Adnl::Callback {
   public:
    Callback(td::actor::ActorId<AdnlHopServer> id) : id_(id) {
    }
    void receive_message(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data) override {
      td::actor::send_closure(id_, &AdnlHopServer::receive_message, src, std::move(data));
    }
    void receive_query(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
    }
   private:
    td::actor::ActorId<AdnlHopServer> id_;
  };
  for (const auto& p : PREFIXES) {
    td::actor::send_closure(adnl_, &Adnl::subscribe, local_id_, p, std::make_unique<Callback>(actor_id(this)));
  }
}

void AdnlHopServer::tear_down() {
  for (const auto& p : PREFIXES) {
    td::actor::send_closure(adnl_, &Adnl::unsubscribe, local_id_, p);
  }
}

void AdnlHopServer::receive_message(AdnlNodeIdShort src, td::BufferSlice data) {
  auto F = fetch_tl_object<ton_api::adnl_hop_Message>(data, true);
  if (F.is_error()) {
    LOG(DEBUG) << "Received bad message: " << F.move_as_error();
    return;
  }
  ton_api::downcast_call(*F.ok(), [&](auto &obj) { this->process_message(src, obj); });
}

void AdnlHopServer::process_message(AdnlNodeIdShort src, ton_api::adnl_hop_encryptedMessage& obj) {
  td::actor::send_closure(keyring_, &keyring::Keyring::decrypt_message, local_id_.pubkey_hash(), std::move(obj.data_),
                          [SelfId = actor_id(this), src](td::Result<td::BufferSlice> R) mutable {
                            if (R.is_error()) {
                              LOG(DEBUG) << "Failed to decrypt incoming message: " << R.move_as_error();
                            } else {
                              td::actor::send_closure(SelfId, &AdnlHopServer::receive_message, src, R.move_as_ok());
                            }
                          });
}

void AdnlHopServer::process_message(AdnlNodeIdShort src, ton_api::adnl_hop_forwardToUdp& obj) {
  td::IPAddress ip;
  if (obj.flags_ & obj.IPV4_MASK) {
    ip.init_host_port(td::IPAddress::ipv4_to_str(obj.ipv4_), obj.port_).ignore();
  } else if (obj.flags_ & obj.IPV6_MASK) {
    ip.init_host_port(td::IPAddress::ipv6_to_str(obj.ipv6_.as_slice()), obj.port_).ignore();
  } else {
    LOG(DEBUG) << "Invalid forwardToUpd: no IP address";
    return;
  }
  // dst_id is AdnlNodeIdShort::zero() because send_udp_packet don't use it (except for logs)
  td::actor::send_closure(network_manager_, &AdnlNetworkManager::send_udp_packet, local_id_, AdnlNodeIdShort::zero(),
                          ip, 0, std::move(obj.data_));
}

void AdnlHopServer::process_message(AdnlNodeIdShort src, ton_api::adnl_hop_forwardToHop& obj) {
  td::actor::send_closure(
      adnl_, &Adnl::send_message, local_id_, AdnlNodeIdShort(obj.dst_),
      create_serialize_tl_object<ton_api::adnl_hop_encryptedMessage>(std::move(obj.encrypted_data_)));
}

void AdnlHopClient::send_packet(AdnlNodeIdShort src, td::IPAddress dst_ip, td::BufferSlice data) {
  auto obj = create_tl_object<ton_api::adnl_hop_forwardToUdp>();
  if (dst_ip.is_ipv4()) {
    obj->flags_ = obj->IPV4_MASK;
    obj->ipv4_ = dst_ip.get_ipv4();
  } else if (dst_ip.is_ipv6()) {
    obj->flags_ = obj->IPV6_MASK;
    obj->ipv6_ = td::Bits128((const unsigned char*)dst_ip.get_ipv6().data());
  } else {
    LOG(DEBUG) << "Failed to send packet: invalid dst_ip";
    return;
  }
  obj->port_ = dst_ip.get_port();
  obj->data_ = std::move(data);
  td::BufferSlice message = serialize_tl_object(obj, true);
  for (size_t i = hops_.size() - 1; i >= 1; --i) {
    auto R = encryptors_[i]->encrypt(message.as_slice());
    if (R.is_error()) {
      LOG(DEBUG) << "Failed to encrypt message with pubkey of " << hops_[i] << ": " << R.move_as_error();
      return;
    }
    message = create_serialize_tl_object<ton_api::adnl_hop_forwardToHop>(hops_[i].bits256_value(), R.move_as_ok());
  }
  td::actor::send_closure(
      adnl_, &Adnl::send_message, local_id_, hops_[0], std::move(message));
}

}  // namespace adnl

}  // namespace ton
