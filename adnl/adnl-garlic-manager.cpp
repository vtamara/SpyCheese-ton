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

namespace ton {

namespace adnl {

AdnlGarlicManager::AdnlGarlicManager(AdnlNodeIdShort local_id, td::uint8 adnl_cat,
                                     td::actor::ActorId<AdnlPeerTable> adnl,
                                     td::actor::ActorId<keyring::Keyring> keyring)
    : local_id_(local_id), adnl_cat_(adnl_cat), adnl_(std::move(adnl)), keyring_(std::move(keyring)) {
}

void AdnlGarlicManager::send_packet(AdnlNodeIdShort src, td::IPAddress dst_ip, td::BufferSlice data) {
  if (!connection_) {
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
  td::BufferSlice message = serialize_tl_object(obj, true);
  const auto& chain = connection_->chain;
  CHECK(!chain.empty() && chain.size() == connection_->encryptors.size());
  for (size_t i = chain.size() - 1; i >= 1; --i) {
    auto id = chain[i];
    auto R = connection_->encryptors[i]->encrypt(message.as_slice());
    if (R.is_error()) {
      LOG(DEBUG) << "Failed to encrypt message with pubkey of " << id << ": " << R.move_as_error();
      return;
    }
    message = create_serialize_tl_object<ton_api::adnl_garlic_forwardToNext>(id.bits256_value(), R.move_as_ok());
  }
  td::actor::send_closure(adnl_, &Adnl::send_message, local_id_, chain[0], std::move(message));
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
  auto addr_list = connection_ ? connection_->addr_list : AdnlAddressList();
  td::actor::send_closure(adnl_, &Adnl::add_id_ex, std::move(id), std::move(addr_list), adnl_cat_,
                          (td::uint32)AdnlLocalIdMode::send_ignore_remote_addr);
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
  TRY_RESULT_PROMISE_ASSIGN(promise, connection_, create_connection(std::move(chain)));
  update_addr_lists();
  promise.set_result(td::Unit());
}

td::Result<std::unique_ptr<AdnlGarlicManager::Connection>> AdnlGarlicManager::create_connection(
    std::vector<AdnlNodeIdShort> chain) {
  std::vector<PublicKey> pubkeys;
  for (size_t i = 0; i < chain.size() + 1; ++i) {
    auto private_key = ton::PrivateKey{ton::privkeys::Ed25519::random()};
    pubkeys.push_back(private_key.compute_public_key());
    td::actor::send_closure(keyring_, &ton::keyring::Keyring::add_key, std::move(private_key), true, [](td::Unit) {});
  }

  std::vector<std::unique_ptr<Encryptor>> encryptors;
  for (AdnlNodeIdShort id : chain) {
    auto E = servers_[id].id_full.pubkey().create_encryptor();
    if (E.is_error()) {
      return td::Status::Error(PSTRING() << "Failed to create encryptor for " << id << ": " << E.move_as_error());
    }
    encryptors.push_back(E.move_as_ok());
  }

  td::BufferSlice message;
  for (int i = (int)chain.size() - 1; i >= 0; --i) {
    auto create_tunnel = create_tl_object<ton_api::adnl_garlic_createTunnelMidpoint>(
        pubkeys[i].tl(), (i == 0 ? local_id_ : chain[i - 1]).bits256_value(), pubkeys[i + 1].compute_short_id().tl());
    if (i == (int)chain.size() - 1) {
      message = serialize_tl_object(create_tunnel, true);
    } else {
      auto R = encryptors[i + 1]->encrypt(message.as_slice());
      if (R.is_error()) {
        return td::Status::Error(PSTRING() << "Failed to encrypt message with pubkey of " << chain[i + 1] << ": "
                                           << R.move_as_error());
      }
      std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> msgs;
      msgs.push_back(std::move(create_tunnel));
      msgs.push_back(
          create_tl_object<ton_api::adnl_garlic_forwardToNext>(chain[i + 1].bits256_value(), R.move_as_ok()));
      message = create_serialize_tl_object<ton_api::adnl_garlic_multipleMessages>(std::move(msgs));
    }
  }
  td::actor::send_closure(adnl_, &Adnl::send_message, local_id_, chain[0], std::move(message));

  std::vector<PublicKeyHash> decrypt_via;
  for (const auto& pub : pubkeys) {
    decrypt_via.push_back(pub.compute_short_id());
  }
  auto connection = std::make_unique<Connection>();
  connection->chain = std::move(chain);
  connection->encryptors = std::move(encryptors);
  connection->endpoint =
      td::actor::create_actor<AdnlInboundTunnelEndpoint>("adnltunnelendpoint", std::move(decrypt_via), keyring_, adnl_);

  class Callback : public Adnl::Callback {
   public:
    Callback(td::actor::ActorId<AdnlInboundTunnelEndpoint> id) : id_(id) {
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
  auto callback = std::make_unique<Callback>(connection->endpoint.get());
  td::BufferSlice prefix =
      create_serialize_tl_object<ton_api::adnl_tunnel_packetPrefix>(pubkeys[0].compute_short_id().tl());
  connection->guard = AdnlSubscribeGuard(adnl_, local_id_, as_slice(prefix).str(), std::move(callback));
  auto addr = td::Ref<AdnlAddressTunnel>(true, connection->chain.back(), pubkeys.back());
  connection->addr_list.set_version(static_cast<td::int32>(td::Clocks::system()));
  connection->addr_list.set_reinit_date(adnl::Adnl::adnl_start_time());
  connection->addr_list.add_addr(std::move(addr));
  return connection;
}

void AdnlGarlicManager::update_addr_lists() {
  auto addr_list = connection_ ? connection_->addr_list : AdnlAddressList();
  for (const auto& p : secret_ids_) {
    td::actor::send_closure(adnl_, &Adnl::add_id_ex, p.second.id_full, addr_list, adnl_cat_,
                            (td::uint32)AdnlLocalIdMode::send_ignore_remote_addr);
  }
}

}  // namespace adnl

}  // namespace ton
