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
#include "adnl-tunnel-server.hpp"
#include "auto/tl/ton_api.hpp"
#include "td/utils/overloaded.h"

namespace ton {

namespace adnl {

static const std::vector<std::string> PREFIXES = {
    Adnl::int_to_bytestring(ton_api::adnl_tunnel_packetPrefix::ID),
    Adnl::int_to_bytestring(ton_api::adnl_tunnel_createMidpoint::ID),
    Adnl::int_to_bytestring(ton_api::adnl_tunnel_encryptedQuery::ID)
};

void AdnlTunnelServer::start_up() {
  class Callback : public Adnl::Callback {
   public:
    Callback(td::actor::ActorId<AdnlTunnelServer> id) : id_(id) {
    }
    void receive_message(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data) override {
      td::actor::send_closure(id_, &AdnlTunnelServer::receive_message, src, std::move(data));
    }
    void receive_query(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
      td::actor::send_closure(id_, &AdnlTunnelServer::receive_query, std::move(data), std::move(promise));
    }
   private:
    td::actor::ActorId<AdnlTunnelServer> id_;
  };
  for (const auto &x : PREFIXES) {
    td::actor::send_closure(adnl_, &Adnl::subscribe, local_id_, x, std::make_unique<Callback>(actor_id(this)));
  }
}

void AdnlTunnelServer::tear_down() {
  for (const auto &x : PREFIXES) {
    td::actor::send_closure(adnl_, &Adnl::unsubscribe, local_id_, x);
  }
}

void AdnlTunnelServer::receive_message(AdnlNodeIdShort src, td::BufferSlice data) {
  if (data.size() <= 4 + 32) {
    LOG(DEBUG) << "dropping too short message from " << src;
    return;
  }
  td::Bits256 id(data.as_slice().remove_prefix(4).ubegin());
  auto it = tunnels_.find(id);
  if (it == tunnels_.end()) {
    LOG(DEBUG) << "dropping message with unknown id " << id << " from " << src;
    return;
  }
  td::actor::send_closure(it->second, &AdnlInboundTunnelMidpoint::receive_packet, src, td::IPAddress(), std::move(data));
}

void AdnlTunnelServer::receive_query(td::BufferSlice data, td::Promise<td::BufferSlice> promise) {
  auto R = fetch_tl_object<ton_api::adnl_tunnel_encryptedQuery>(data, true);
  if (R.is_ok()) {
    data = std::move(R.move_as_ok()->data_);
    td::actor::send_closure(
        keyring_, &keyring::Keyring::decrypt_message, local_id_.pubkey_hash(), std::move(data),
        [SelfId = actor_id(this), promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_error(R.move_as_error());
          } else {
            td::actor::send_closure(SelfId, &AdnlTunnelServer::receive_query, R.move_as_ok(), std::move(promise));
          }
        });
    return;
  }

  TRY_RESULT_PROMISE(promise, query, fetch_tl_object<ton_api::adnl_tunnel_createMidpoint>(data, true));
  if (tunnels_.count(query->message_prefix_)) {
    promise.set_error(td::Status::Error("duplicate id"));
    return;
  }
  tunnels_[query->message_prefix_] = td::actor::create_actor<AdnlInboundTunnelMidpoint>(
      "adnltunnel", PublicKey(query->encrypt_via_), AdnlNodeIdShort(query->proxy_to_), local_id_, keyring_, adnl_);

  ton_api::downcast_call(
      *query->query_to_prev_,
      td::overloaded(
          [&](ton_api::adnl_tunnel_queryToPrevNone &) {
            promise.set_value(serialize_tl_object(create_tl_object<ton::ton_api::tonNode_success>(), true));
          },
          [&](ton_api::adnl_tunnel_queryToPrev &obj) {
            td::actor::send_closure(
                adnl_, &Adnl::send_query, local_id_, AdnlNodeIdShort(obj.addr_), "querytoprev", std::move(promise),
                td::Timestamp::in(10.0),
                create_serialize_tl_object<ton_api::adnl_tunnel_encryptedQuery>(std::move(obj.data_)));
          }));
}

}  // namespace adnl

}  // namespace ton
