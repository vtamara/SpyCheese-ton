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
#include "adnl-garlic-manager.hpp"
#include "td/utils/Random.h"
#include "adnl-address-list.hpp"
#include "td/utils/overloaded.h"
#include "auto/tl/ton_api.hpp"

namespace ton {

namespace adnl {

AdnlGarlicManager::AdnlGarlicManager(AdnlNodeIdShort local_id, td::uint8 adnl_cat,
                                     td::actor::ActorId<AdnlPeerTable> adnl,
                                     td::actor::ActorId<keyring::Keyring> keyring,
                                     std::shared_ptr<dht::DhtGlobalConfig> dht_config)
    : local_id_(local_id)
    , adnl_cat_(adnl_cat)
    , adnl_(std::move(adnl))
    , keyring_(std::move(keyring))
    , dht_config_(std::move(dht_config)) {
}

void AdnlGarlicManager::start_up() {
  // Creating DHT node
  if (use_secret_dht()) {
    auto pk = ton::PrivateKey{ton::privkeys::Ed25519::random()};
    auto pub = pk.compute_public_key();
    td::actor::send_closure(keyring_, &ton::keyring::Keyring::add_key, pk, true, [](td::Unit) {});
    auto dht_id = AdnlNodeIdFull(pub);
    create_secret_id(dht_id, [](td::Result<td::Unit>) {});
    auto R = dht::Dht::create_client(dht_id.compute_short_id(), "", dht_config_, keyring_, adnl_);
    if (R.is_error()) {
      LOG(ERROR) << "Failed to create secret DHT node: " << R.move_as_error();
      return;
    }
    secret_dht_node_ = R.move_as_ok();
    for (const auto& id : secret_ids_) {
      td::actor::send_closure(adnl_, &Adnl::set_custom_dht_node, id.first, secret_dht_node_.get());
    }
  }
}

void AdnlGarlicManager::send_packet(AdnlNodeIdShort src, td::IPAddress dst_ip, td::BufferSlice data) {
  if (!connection_ || !connection_->ready) {
    LOG(DEBUG) << "Failed to send packet: connection is not ready";
    return;
  }
  auto obj = create_tl_object<ton_api::adnl_garlic_forwardToUdp>();
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
  wrap_send_message(*connection_, std::move(obj));
}

void AdnlGarlicManager::add_server(AdnlNodeIdFull server) {
  AdnlNodeIdShort id = server.compute_short_id();
  if (servers_.count(id)) {
    LOG(DEBUG) << "Duplicate server " << id;
    return;
  }
  servers_[id].id_full = server;
  servers_vec_.push_back(id);
}

void AdnlGarlicManager::create_secret_id(AdnlNodeIdFull id, td::Promise<td::Unit> promise) {
  AdnlNodeIdShort id_short = id.compute_short_id();
  if (secret_ids_.count(id_short)) {
    promise.set_error(td::Status::Error("Duplicate secret id"));
    return;
  }
  secret_ids_[id_short].id_full = id;
  auto addr_list = connection_ && connection_->ready ? connection_->addr_list : AdnlAddressList();
  td::actor::send_closure(adnl_, &Adnl::add_id_ex, std::move(id), std::move(addr_list), adnl_cat_, local_id_mode());
  if (use_secret_dht() && !secret_dht_node_.empty()) {
    td::actor::send_closure(adnl_, &Adnl::set_custom_dht_node, id_short, secret_dht_node_.get());
  }
  promise.set_result(td::Unit());
}

void AdnlGarlicManager::init_connection(size_t chain_length, td::Promise<td::Unit> promise) {
  if (chain_length == 0) {
    promise.set_error(td::Status::Error("Invalid chain length"));
    return;
  }
  if (chain_length > servers_vec_.size()) {
    promise.set_error(td::Status::Error("Not enough servers"));
    return;
  }
  for (size_t i = 0; i < chain_length; ++i) {
    std::swap(servers_vec_[i], servers_vec_[i + td::Random::secure_uint32() % (servers_vec_.size() - i)]);
  }
  std::vector<AdnlNodeIdShort> chain(servers_vec_.begin(), servers_vec_.begin() + chain_length);

  LOG(INFO) << "Creating garlic connection, local_id = " << local_id_;
  for (size_t i = 0; i < chain.size(); ++i) {
    LOG(INFO) << "  Node #" << i << " : " << chain[i];
  }

  std::vector<PublicKey> pubkeys;
  for (size_t i = 0; i < chain.size() + 1; ++i) {
    auto private_key = ton::PrivateKey{ton::privkeys::Ed25519::random()};
    pubkeys.push_back(private_key.compute_public_key());
    td::actor::send_closure(keyring_, &ton::keyring::Keyring::add_key, std::move(private_key), true, [](td::Unit) {});
  }

  std::vector<std::unique_ptr<Encryptor>> encryptors;
  for (AdnlNodeIdShort id : chain) {
    TRY_RESULT_PROMISE(promise, enc, servers_[id].id_full.pubkey().create_encryptor());
    encryptors.push_back(std::move(enc));
  }

  std::vector<PublicKeyHash> decrypt_via;
  for (const auto& pub : pubkeys) {
    decrypt_via.push_back(pub.compute_short_id());
  }
  connection_ = std::make_unique<Connection>();
  connection_->chain = std::move(chain);
  connection_->encryptors = std::move(encryptors);

  AdnlCategoryMask cat_mask;
  cat_mask.set(adnl_cat_);

  class TunnelCallback : public AdnlInboundTunnelEndpoint::Callback {
   public:
    TunnelCallback(td::actor::ActorId<AdnlGarlicManager> id) : id_(id) {
    }
    void receive_custom_message(size_t sender_id, td::BufferSlice data) override {
      td::actor::send_closure(id_, &AdnlGarlicManager::receive_custom_message, sender_id, std::move(data));
    }
   private:
    td::actor::ActorId<AdnlGarlicManager> id_;
  };
  auto tunnel_callback = std::make_unique<TunnelCallback>(actor_id(this));
  connection_->endpoint = td::actor::create_actor<AdnlInboundTunnelEndpoint>(
      "adnltunnelendpoint", std::move(decrypt_via), cat_mask, std::move(tunnel_callback), keyring_, adnl_);

  class AdnlCallback : public Adnl::Callback {
   public:
    AdnlCallback(td::actor::ActorId<AdnlInboundTunnelEndpoint> id) : id_(id) {
    }
    void receive_message(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data) override {
      td::actor::send_closure(id_, &AdnlInboundTunnelEndpoint::receive_packet, src, td::IPAddress(), std::move(data));
    }
    void receive_query(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
    }
   private:
    td::actor::ActorId<AdnlInboundTunnelEndpoint> id_;
  };
  auto adnl_callback = std::make_unique<AdnlCallback>(connection_->endpoint.get());
  td::BufferSlice prefix =
      create_serialize_tl_object<ton_api::adnl_tunnel_packetPrefix>(pubkeys[0].compute_short_id().tl());
  connection_->guard = AdnlSubscribeGuard(adnl_, local_id_, as_slice(prefix).str(), std::move(adnl_callback));
  auto addr = td::Ref<AdnlAddressTunnel>(true, connection_->chain.back(), pubkeys.back());
  connection_->addr_list.set_version(static_cast<td::int32>(td::Clocks::system()));
  connection_->addr_list.set_reinit_date(adnl::Adnl::adnl_start_time());
  connection_->addr_list.add_addr(std::move(addr));

  std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> msgs;
  for (size_t i = 0; i < connection_->chain.size(); ++i) {
    msgs.push_back(create_tl_object<ton_api::adnl_garlic_createTunnelMidpoint>(
        pubkeys[i].tl(), (i == 0 ? local_id_ : connection_->chain[i - 1]).bits256_value(),
        pubkeys[i + 1].compute_short_id().tl()));
  }
  wrap_send_message(*connection_, std::move(msgs));

  connection_->pubkeys = std::move(pubkeys);
  connection_->ready_promise = std::move(promise);
  connection_->ready_ttl = td::Timestamp::in(10.0);
  td::Random::secure_bytes(connection_->init_nonce.as_slice());
  wrap_send_message(*connection_, create_tl_object<ton_api::adnl_garlic_ping>(
                                      connection_->pubkeys.back().compute_short_id().tl(), connection_->init_nonce));
  alarm_timestamp() = connection_->ready_ttl;
}

void AdnlGarlicManager::receive_custom_message(size_t sender_id, td::BufferSlice data) {
  auto F = fetch_tl_object<ton_api::adnl_garlic_pong>(data, true);
  if (F.is_error()) {
    return;
  }
  if (connection_ && !connection_->ready && connection_->init_nonce == F.ok()->nonce_) {
    connection_->ready = true;
    update_addr_lists();
    connection_->ready_promise.set_result(td::Unit());
    alarm_timestamp() = td::Timestamp::in(td::Random::fast(60.0, 120.0));
  }
}

void AdnlGarlicManager::alarm() {
  if (!connection_) {
    return;
  }
  if (!connection_->ready && connection_->ready_ttl.is_in_past()) {
    connection_->ready_promise.set_error(td::Status::Error(ErrorCode::timeout, "timeout"));
    connection_ = nullptr;
    return;
  }
  if (connection_->ready) {
    wrap_send_message(*connection_, create_tl_object<ton_api::adnl_garlic_ping>(
                                        connection_->pubkeys.back().compute_short_id().tl(), td::Bits256::zero()));
    alarm_timestamp() = td::Timestamp::in(td::Random::fast(60.0, 120.0));
  }
}

void AdnlGarlicManager::update_addr_lists() {
  auto addr_list = connection_ && connection_->ready ? connection_->addr_list : AdnlAddressList();
  for (const auto& p : secret_ids_) {
    td::actor::send_closure(adnl_, &Adnl::add_id_ex, p.second.id_full, addr_list, adnl_cat_, local_id_mode());
  }
}

void AdnlGarlicManager::wrap_send_message(const Connection& connection,
                                          std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> msgs) {
  td::BufferSlice message;
  CHECK(msgs.size() == connection.chain.size());
  for (int i = (int)connection.chain.size() - 1; i >= 0; --i) {
    auto obj = std::move(msgs[i]);
    if (i == (int)connection.chain.size() - 1) {
      if (!obj) {
        obj = create_tl_object<ton_api::adnl_garlic_multipleMessages>();
      }
    } else {
      auto R = connection.encryptors[i + 1]->encrypt(message.as_slice());
      if (R.is_error()) {
        LOG(DEBUG) << "Failed to encrypt message with pubkey of " << connection.chain[i + 1] << ": "
                   << R.move_as_error();
        return;
      }
      auto forward =
          create_tl_object<ton_api::adnl_garlic_forwardToNext>(connection.chain[i + 1].bits256_value(), R.move_as_ok());
      if (obj) {
        ton_api::downcast_call(
            *obj,
            td::overloaded([&](ton_api::adnl_garlic_multipleMessages& x) { x.messages_.push_back(std::move(forward)); },
                           [&](auto&) {
                             std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> m;
                             m.push_back(std::move(obj));
                             m.push_back(std::move(forward));
                             obj = create_tl_object<ton_api::adnl_garlic_multipleMessages>(std::move(m));
                           }));
      } else {
        obj = std::move(forward);
      }
    }
    message = serialize_tl_object(obj, true);
  }
  td::actor::send_closure(adnl_, &Adnl::send_message, local_id_, connection_->chain[0], std::move(message));
}

void AdnlGarlicManager::wrap_send_message(const Connection& connection,
                                          tl_object_ptr<ton_api::adnl_garlic_Message> msg) {
  std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> msgs(connection.chain.size());
  msgs.back() = std::move(msg);
  wrap_send_message(connection, std::move(msgs));
}

}  // namespace adnl

}  // namespace ton
