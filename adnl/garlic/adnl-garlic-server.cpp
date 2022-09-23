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
    Adnl::int_to_bytestring(ton_api::adnl_garlic_forwardToNextChannel::ID),
    Adnl::int_to_bytestring(ton_api::adnl_garlic_createTunnelMidpoint::ID),
    Adnl::int_to_bytestring(ton_api::adnl_garlic_createChannel::ID),
    Adnl::int_to_bytestring(ton_api::adnl_garlic_multipleMessages::ID),
    Adnl::int_to_bytestring(ton_api::adnl_garlic_encryptedMessage::ID),
    Adnl::int_to_bytestring(ton_api::adnl_garlic_encryptedMessageChannel::ID),
    Adnl::int_to_bytestring(ton_api::adnl_garlic_ping::ID)
};
static const double TUNNEL_TTL = 300.0;

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

  auto X = create_hash_tl_object<ton_api::adnl_garlic_publicOverlayId>();
  td::BufferSlice b{32};
  b.as_slice().copy_from(as_slice(X));
  overlay_id_full_ = overlay::OverlayIdFull{std::move(b)};
  overlay_id_ = overlay_id_full_.compute_short_id();
  td::actor::send_closure(overlays_, &overlay::Overlays::create_public_overlay, local_id_, overlay_id_full_.clone(),
                          std::make_unique<overlay::Overlays::EmptyCallback>(), overlay::OverlayPrivacyRules{},
                          R"({ "type": "garlic" })");

  alarm_timestamp() = td::Timestamp::in(60.0);
}

void AdnlGarlicServer::tear_down() {
  td::actor::send_closure(overlays_, &overlay::Overlays::delete_overlay, local_id_, overlay_id_);
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

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_encryptedMessageChannel& obj) {
  auto it = garlic_channels_.find(obj.key_id_);
  if (it == garlic_channels_.end()) {
    LOG(DEBUG) << "Failed to decrypt incoming message: no such channel";
    return;
  }
  auto R = it->second.decryptor->decrypt(std::move(obj.data_));
  if (R.is_error()) {
    LOG(DEBUG) << "Failed to decrypt incoming message: " << R.move_as_error();
  } else {
    receive_message(src, R.move_as_ok());
    it->second.ttl = td::Timestamp::in(TUNNEL_TTL);
  }
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

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_forwardToNextChannel& obj) {
  td::actor::send_closure(adnl_, &Adnl::send_message, local_id_, AdnlNodeIdShort(obj.dst_),
                          create_serialize_tl_object<ton_api::adnl_garlic_encryptedMessageChannel>(
                              obj.key_id_, std::move(obj.encrypted_data_)));
}

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_createTunnelMidpoint& obj) {
  if (tunnels_.count(obj.message_prefix_)) {
    LOG(DEBUG) << "Failed to create tunnel: duplicate id";
    return;
  }

  class Callback : public Adnl::Callback {
   public:
    Callback(td::actor::ActorId<AdnlGarlicServer> actor, td::actor::ActorId<AdnlInboundTunnelMidpoint> tunnel,
             td::Bits256 id)
        : actor_(std::move(actor)), tunnel_(std::move(tunnel)), id_(id) {
    }
    void receive_message(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data) override {
      td::actor::send_closure(tunnel_, &AdnlInboundTunnelMidpoint::receive_packet, src, td::IPAddress(),
                              std::move(data));
      td::actor::send_closure(actor_, &AdnlGarlicServer::update_tunnel_ttl, id_);
    }
    void receive_query(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
    }

   private:
    td::actor::ActorId<AdnlGarlicServer> actor_;
    td::actor::ActorId<AdnlInboundTunnelMidpoint> tunnel_;
    td::Bits256 id_;
  };
  auto actor = td::actor::create_actor<AdnlInboundTunnelMidpoint>(
      "adnltunnel", PublicKey(obj.encrypt_via_), AdnlNodeIdShort(obj.proxy_to_), local_id_, keyring_, adnl_);
  auto callback = std::make_unique<Callback>(actor_id(this), actor.get(), obj.message_prefix_);
  td::BufferSlice prefix = create_serialize_tl_object<ton_api::adnl_tunnel_packetPrefix>(obj.message_prefix_);
  tunnels_.emplace(obj.message_prefix_,
                   TunnelMidpoint{std::move(actor),
                                  AdnlSubscribeGuard(adnl_, local_id_, as_slice(prefix).str(), std::move(callback)),
                                  td::Timestamp::in(TUNNEL_TTL)});
}

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_createChannel& obj) {
  PrivateKey key(obj.key_);
  td::Bits256 id = key.compute_short_id().bits256_value();
  if (garlic_channels_.count(id)) {
    LOG(DEBUG) << "Failed to create channel: duplicate id";
    return;
  }
  auto R = key.create_decryptor();
  if (garlic_channels_.count(id)) {
    LOG(DEBUG) << "Failed to create decryptor for channel: " << R.move_as_error();
    return;
  }
  garlic_channels_.emplace(id, GarlicChannel{R.move_as_ok(), td::Timestamp::in(TUNNEL_TTL)});
}

void AdnlGarlicServer::process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_ping& obj) {
  auto it = tunnels_.find(obj.tunnel_id_);
  if (it == tunnels_.end()) {
    LOG(DEBUG) << "Unknown tunnel " << obj.tunnel_id_;
    return;
  }
  it->second.ttl = td::Timestamp::in(TUNNEL_TTL);
  td::actor::send_closure(it->second.actor, &AdnlInboundTunnelMidpoint::send_custom_message,
                          create_serialize_tl_object<ton_api::adnl_garlic_pong>(obj.nonce_));
}

void AdnlGarlicServer::update_tunnel_ttl(td::Bits256 id) {
  auto it = tunnels_.find(id);
  if (it == tunnels_.end()) {
    return;
  }
  it->second.ttl = td::Timestamp::in(TUNNEL_TTL);
}

void AdnlGarlicServer::alarm() {
  auto it = tunnels_.begin();
  while (it != tunnels_.end()) {
    if (it->second.ttl && it->second.ttl.is_in_past()) {
      it = tunnels_.erase(it);
    } else {
      ++it;
    }
  }
  auto it2 = garlic_channels_.begin();
  while (it2 != garlic_channels_.end()) {
    if (it2->second.ttl && it2->second.ttl.is_in_past()) {
      it2 = garlic_channels_.erase(it2);
    } else {
      ++it2;
    }
  }
  alarm_timestamp() = td::Timestamp::in(60.0);
}

}  // namespace adnl

}  // namespace ton
