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
#include "adnl/adnl-address-list.hpp"
#include "td/utils/overloaded.h"
#include "auto/tl/ton_api.hpp"

namespace ton {

namespace adnl {

AdnlGarlicManager::Connection::Connection(AdnlNodeIdShort local_id, std::vector<AdnlNodeIdFull> chain,
                                          std::unique_ptr<Callback> callback, td::uint8 adnl_cat,
                                          td::actor::ActorId<Adnl> adnl, td::actor::ActorId<keyring::Keyring> keyring)
    : local_id_(local_id)
    , callback_(std::move(callback))
    , adnl_cat_(adnl_cat)
    , adnl_(std::move(adnl))
    , keyring_(std::move(keyring))
    , chain_full_(std::move(chain)) {
  CHECK(!chain_full_.empty());
}

void AdnlGarlicManager::Connection::start_up() {
  LOG(INFO) << "Creating garlic connection, local_id = " << local_id_;
  for (size_t i = 0; i < chain_full_.size(); ++i) {
    chain_.push_back(chain_full_[i].compute_short_id());
    LOG(INFO) << "  Node #" << i << " : " << chain_.back();
    auto E = chain_full_[i].pubkey().create_encryptor();
    if (E.is_error()) {
      LOG(WARNING) << "Failed to create encryptor for " << chain_.back() << ": " << E.move_as_error();
      callback_->on_fail();
      stop();
      return;
    }
    encryptors_.push_back(E.move_as_ok());
  }
  std::vector<PublicKeyHash> decrypt_via;
  for (size_t i = 0; i < chain_.size() + 1; ++i) {
    PrivateKey private_key(privkeys::Ed25519::random());
    pubkeys_.push_back(private_key.compute_public_key());
    decrypt_via.push_back(pubkeys_.back().compute_short_id());
    td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(private_key), true, [](td::Unit) {});
  }

  AdnlCategoryMask cat_mask;
  cat_mask.set(adnl_cat_);
  class TunnelCallback : public AdnlInboundTunnelEndpoint::Callback {
   public:
    TunnelCallback(td::actor::ActorId<AdnlGarlicManager::Connection> id) : id_(id) {
    }
    void receive_custom_message(size_t sender_id, td::BufferSlice data) override {
      td::actor::send_closure(id_, &AdnlGarlicManager::Connection::receive_custom_message, sender_id, std::move(data));
    }
   private:
    td::actor::ActorId<AdnlGarlicManager::Connection> id_;
  };
  auto tunnel_callback = std::make_unique<TunnelCallback>(actor_id(this));
  endpoint_ = td::actor::create_actor<AdnlInboundTunnelEndpoint>("adnltunnelendpoint", std::move(decrypt_via), cat_mask,
                                                                 std::move(tunnel_callback), keyring_, adnl_);

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
  auto adnl_callback = std::make_unique<AdnlCallback>(endpoint_.get());
  td::BufferSlice prefix =
      create_serialize_tl_object<ton_api::adnl_tunnel_packetPrefix>(pubkeys_[0].compute_short_id().tl());
  guard_ = AdnlSubscribeGuard(adnl_, local_id_, as_slice(prefix).str(), std::move(adnl_callback));

  td::Random::secure_bytes(init_nonce_.as_slice());
  got_init_pong_.resize(chain_.size(), false);
  send_init_message();
  alarm_timestamp() = td::Timestamp::in(3.0);
}

void AdnlGarlicManager::Connection::send_init_message() {
  LOG(INFO) << "Sending init message";
  std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> msgs;
  for (size_t i = 0; i < chain_.size(); ++i) {
    std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> cur_msgs;
    td::Bits256 tunnel_id = pubkeys_[i + 1].compute_short_id().tl();
    cur_msgs.push_back(create_tl_object<ton_api::adnl_garlic_createTunnelMidpoint>(
        pubkeys_[i].tl(), (i == 0 ? local_id_ : chain_[i - 1]).bits256_value(),
        tunnel_id));
    cur_msgs.push_back(create_tl_object<ton_api::adnl_garlic_ping>(tunnel_id, init_nonce_));
    msgs.push_back(create_tl_object<ton_api::adnl_garlic_multipleMessages>(std::move(cur_msgs)));
  }
  wrap_send_message(std::move(msgs));
}

void AdnlGarlicManager::Connection::tear_down() {
  for (const PublicKey& pub : pubkeys_) {
    td::actor::send_closure(keyring_, &keyring::Keyring::del_key, pub.compute_short_id(), [](td::Unit) {});
  }
}

void AdnlGarlicManager::Connection::send_packet(AdnlNodeIdShort src, td::IPAddress dst_ip, td::BufferSlice data) {
  if (!ready_) {
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
  wrap_send_message(std::move(obj));
}

void AdnlGarlicManager::Connection::alarm() {
  if (!ready_) {
    if (init_retries_remaining_ > 0) {
      --init_retries_remaining_;
      send_init_message();
      alarm_timestamp() = td::Timestamp::in(3.0);
      return;
    }
    size_t causer = 0;
    while (causer < got_init_pong_.size() && got_init_pong_[causer]) {
      ++causer;
    }
    CHECK(causer < got_init_pong_.size());
    LOG(INFO) << "Falied to create connection: timeout, causer is #" << causer << " (" << chain_[causer] << ")";
    callback_->on_fail(chain_[causer]);
    stop();
  } else if (!sent_ping_) {
    sent_ping_ = true;
    td::Random::secure_bytes(ping_nonce_.as_slice());
    ping_retries_remaining_ = 3;
    wrap_send_message(
        create_tl_object<ton_api::adnl_garlic_ping>(pubkeys_.back().compute_short_id().tl(), ping_nonce_));
    alarm_timestamp() = td::Timestamp::in(2.0);
  } else if (ping_retries_remaining_ > 0) {
    --ping_retries_remaining_;
    wrap_send_message(
        create_tl_object<ton_api::adnl_garlic_ping>(pubkeys_.back().compute_short_id().tl(), ping_nonce_));
    alarm_timestamp() = td::Timestamp::in(2.0);
  } else {
    LOG(INFO) << "Ping timeout, closing connection";
    callback_->on_fail();
    stop();
  }
}

void AdnlGarlicManager::Connection::receive_custom_message(size_t sender_id, td::BufferSlice data) {
  CHECK(sender_id < chain_.size());
  auto F = fetch_tl_object<ton_api::adnl_garlic_pong>(data, true);
  if (F.is_error()) {
    return;
  }
  td::Bits256 nonce = F.ok()->nonce_;
  if (!ready_) {
    if (nonce != init_nonce_) {
      return;
    }
    if (!got_init_pong_[sender_id]) {
      LOG(INFO) << "Got init pong from #" << sender_id << " (" << chain_[sender_id] << ")";
      got_init_pong_[sender_id] = true;
    }
    if (sender_id == chain_.size() - 1) {
      set_ready();
    }
  } else {
    if (nonce != ping_nonce_ || sender_id != chain_.size() - 1) {
      return;
    }
    sent_ping_ = false;
    alarm_timestamp() = td::Timestamp::in(td::Random::fast(10.0, 15.0));
  }
}

void AdnlGarlicManager::Connection::set_ready() {
  CHECK(!ready_);
  ready_ = true;
  LOG(INFO) << "Connection is ready";
  td::Ref<AdnlAddressTunnel> addr(true, chain_.back(), pubkeys_.back());
  AdnlAddressList addr_list;
  addr_list.set_version(static_cast<td::int32>(td::Clocks::system()));
  addr_list.set_reinit_date(adnl::Adnl::adnl_start_time());
  addr_list.add_addr(std::move(addr));
  callback_->on_ready(std::move(addr_list));
  alarm_timestamp() = td::Timestamp::in(td::Random::fast(10.0, 15.0));
}

void AdnlGarlicManager::Connection::wrap_send_message(std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> msgs) {
  td::BufferSlice message;
  CHECK(msgs.size() == chain_.size());
  for (int i = (int)chain_.size() - 1; i >= 0; --i) {
    auto obj = std::move(msgs[i]);
    if (i == (int)chain_.size() - 1) {
      if (!obj) {
        obj = create_tl_object<ton_api::adnl_garlic_multipleMessages>();
      }
    } else {
      auto R = encryptors_[i + 1]->encrypt(message.as_slice());
      if (R.is_error()) {
        LOG(DEBUG) << "Failed to encrypt message with pubkey of " << chain_[i + 1] << ": "
                   << R.move_as_error();
        return;
      }
      auto forward =
          create_tl_object<ton_api::adnl_garlic_forwardToNext>(chain_[i + 1].bits256_value(), R.move_as_ok());
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
  td::actor::send_closure(adnl_, &Adnl::send_message, local_id_, chain_[0], std::move(message));
}

void AdnlGarlicManager::Connection::wrap_send_message(tl_object_ptr<ton_api::adnl_garlic_Message> msg) {
  std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> msgs(chain_.size());
  msgs.back() = std::move(msg);
  wrap_send_message(std::move(msgs));
}

}  // namespace adnl

}  // namespace ton
