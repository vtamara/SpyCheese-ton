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
#include "adnl-garlic-server.hpp"
#include "auto/tl/ton_api.hpp"

namespace ton {

namespace adnl {

static const std::vector<std::string> PREFIXES = {
    Adnl::int_to_bytestring(ton_api::adnl_garlic_forwardToUdp::ID),
    Adnl::int_to_bytestring(ton_api::adnl_garlic_forwardToNext::ID),
    Adnl::int_to_bytestring(ton_api::adnl_garlic_createTunnelMidpoint::ID),
    Adnl::int_to_bytestring(ton_api::adnl_garlic_multipleMessages::ID),
    Adnl::int_to_bytestring(ton_api::adnl_garlic_encryptedMessage::ID)
};

void AdnlGarlicServer::start_up() {
  class Callback : public Adnl::Callback {
   public:
    Callback(td::actor::ActorId<AdnlGarlicServer> id) : id_(id) {
    }
    void receive_message(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data) override {
      td::actor::send_closure(id_, &AdnlGarlicServer::receive_message, src, std::move(data));
    }
    void receive_query(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
    }
   private:
    td::actor::ActorId<AdnlGarlicServer> id_;
  };
  for (const auto& p : PREFIXES) {
    td::actor::send_closure(adnl_, &Adnl::subscribe, local_id_, p, std::make_unique<Callback>(actor_id(this)));
  }
}

void AdnlGarlicServer::tear_down() {
  for (const auto& p : PREFIXES) {
    td::actor::send_closure(adnl_, &Adnl::unsubscribe, local_id_, p);
  }
}

void AdnlGarlicServer::receive_message(AdnlNodeIdShort src, td::BufferSlice data) {
  auto F = fetch_tl_object<ton_api::adnl_garlic_Message>(data, true);
  if (F.is_error()) {
    LOG(DEBUG) << "Received bad message: " << F.move_as_error();
    return;
  }
  process_message(src, F.move_as_ok());
}

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, tl_object_ptr<ton_api::adnl_garlic_Message> obj) {
  ton_api::downcast_call(*obj, [&](auto &x) { this->process_message(src, x); });
}

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_encryptedMessage& obj) {
  td::actor::send_closure(keyring_, &keyring::Keyring::decrypt_message, local_id_.pubkey_hash(), std::move(obj.data_),
                          [SelfId = actor_id(this), src](td::Result<td::BufferSlice> R) mutable {
                            if (R.is_error()) {
                              LOG(DEBUG) << "Failed to decrypt incoming message: " << R.move_as_error();
                            } else {
                              td::actor::send_closure(SelfId, &AdnlGarlicServer::receive_message, src, R.move_as_ok());
                            }
                          });
}

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_multipleMessages& obj) {
  for (auto& msg : obj.messages_) {
    process_message(src, std::move(msg));
  }
}

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_forwardToUdp& obj) {
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

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_forwardToNext& obj) {
  td::actor::send_closure(
      adnl_, &Adnl::send_message, local_id_, AdnlNodeIdShort(obj.dst_),
      create_serialize_tl_object<ton_api::adnl_garlic_encryptedMessage>(std::move(obj.encrypted_data_)));
}

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_createTunnelMidpoint& obj) {
  if (tunnels_.count(obj.message_prefix_)) {
    LOG(DEBUG) << "Failed to create tunnel: duplicate id";
    return;
  }

  class Callback : public Adnl::Callback {
   public:
    Callback(td::actor::ActorId<AdnlInboundTunnelMidpoint> id) : id_(id) {
    }
    void receive_message(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data) override {
      td::actor::send_closure(id_, &AdnlInboundTunnelMidpoint::receive_packet, src, td::IPAddress(), std::move(data));
    }
    void receive_query(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
    }
   private:
    td::actor::ActorId<AdnlInboundTunnelMidpoint> id_;
  };
  auto actor = td::actor::create_actor<AdnlInboundTunnelMidpoint>(
      "adnltunnel", PublicKey(obj.encrypt_via_), AdnlNodeIdShort(obj.proxy_to_), local_id_, keyring_, adnl_);
  auto callback = std::make_unique<Callback>(actor.get());
  td::BufferSlice prefix = create_serialize_tl_object<ton_api::adnl_tunnel_packetPrefix>(obj.message_prefix_);
  tunnels_.emplace(obj.message_prefix_,
                   TunnelMidpoint{std::move(actor),
                                  AdnlSubscribeGuard(adnl_, local_id_, as_slice(prefix).str(), std::move(callback))});
}

}  // namespace adnl

}  // namespace ton
