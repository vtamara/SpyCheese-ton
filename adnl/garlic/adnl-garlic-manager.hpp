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
#pragma once

#include "adnl/adnl.h"
#include "adnl-tunnel.h"
#include "adnl/adnl.h"
#include "keys/encryptor.h"
#include "adnl/utils.hpp"
#include "dht/dht.h"
#include "overlay/overlays.h"

namespace ton {

namespace adnl {

struct AdnlGarlicConfig {
  size_t chain_length = 3;
  double start_delay = 5.0;
  bool use_secret_dht = false;
  std::shared_ptr<dht::DhtGlobalConfig> dht_config;
};

class AdnlGarlicManager : public AdnlNetworkManager::CustomSender {
 public:
  AdnlGarlicManager(AdnlNodeIdShort local_id, td::uint8 adnl_cat, td::actor::ActorId<Adnl> adnl,
                    td::actor::ActorId<keyring::Keyring> keyring, td::actor::ActorId<overlay::Overlays> overlays,
                    AdnlGarlicConfig config);

  void start_up() override;
  void tear_down() override;
  void alarm() override;
  void send_packet(AdnlNodeIdShort src, td::IPAddress dst_ip, td::BufferSlice data) override;

  void create_secret_id(AdnlNodeIdFull id, td::Promise<td::Unit> promise);
  void create_secret_id_short(AdnlNodeIdShort id, td::Promise<td::Unit> promise);

 private:
  AdnlNodeIdShort local_id_;
  td::uint8 adnl_cat_;
  td::actor::ActorId<Adnl> adnl_;
  td::actor::ActorId<keyring::Keyring> keyring_;
  td::actor::ActorId<overlay::Overlays> overlays_;
  AdnlGarlicConfig config_;

  td::Timestamp create_connection_at_;

  overlay::OverlayIdFull overlay_id_full_;
  overlay::OverlayIdShort overlay_id_;

  struct Server {
    AdnlNodeIdFull id_full = {};
    td::uint32 version = 0;
    td::uint32 ignore_until = 0;
  };
  std::map<AdnlNodeIdShort, Server> servers_;

  class Connection : public td::actor::Actor {
   public:
    class Callback {
     public:
      virtual ~Callback() = default;
      virtual void on_ready(AdnlAddressList addr_list) = 0;
      virtual void on_fail(AdnlNodeIdShort causer = AdnlNodeIdShort::zero()) = 0;
    };

    Connection(AdnlNodeIdShort local_id, std::vector<AdnlNodeIdFull> chain, std::unique_ptr<Callback> callback,
               td::uint8 adnl_cat, td::actor::ActorId<Adnl> adnl, td::actor::ActorId<keyring::Keyring> keyring);
    void start_up() override;
    void send_packet(AdnlNodeIdShort src, td::IPAddress dst_ip, td::BufferSlice data);
    void alarm() override;

   private:
    AdnlNodeIdShort local_id_;
    std::unique_ptr<Callback> callback_;
    td::uint8 adnl_cat_;
    td::actor::ActorId<Adnl> adnl_;
    td::actor::ActorId<keyring::Keyring> keyring_;
    std::vector<AdnlNodeIdFull> chain_full_;
    std::vector<AdnlNodeIdShort> chain_;
    std::vector<std::unique_ptr<Encryptor>> init_encryptors_;
    td::actor::ActorOwn<AdnlInboundTunnelEndpoint> endpoint_;
    AdnlSubscribeGuard guard_;
    std::vector<PublicKey> pubkeys_;

    struct ChannelEncryptor {
      PrivateKey key;
      td::Bits256 id;
      std::unique_ptr<Encryptor> encryptor;
    };
    std::vector<ChannelEncryptor> encryptors_;

    bool ready_ = false;
    size_t init_retries_remaining_;
    td::Bits256 init_nonce_;
    std::vector<bool> got_init_pong_;

    bool sent_ping_ = false;
    size_t ping_retries_remaining_;
    td::Bits256 ping_nonce_;

    void send_init_message();
    void set_ready();
    void receive_custom_message(size_t sender_id, td::BufferSlice data);
    void wrap_send_message(std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> msgs);
    void wrap_send_message(tl_object_ptr<ton_api::adnl_garlic_Message> msg);
  };
  td::actor::ActorOwn<Connection> connection_;
  AdnlAddressList addr_list_;

  struct SecretId {
    AdnlNodeIdFull id_full;
  };
  std::map<AdnlNodeIdShort, SecretId> secret_ids_;
  td::actor::ActorOwn<dht::Dht> secret_dht_node_;

  td::uint32 local_id_mode() const {
    return (td::uint32)AdnlLocalIdMode::send_ignore_remote_addr |
           (config_.use_secret_dht ? (td::uint32)AdnlLocalIdMode::custom_dht_node : 0);
  }

  void got_servers_from_overlay(std::vector<std::pair<AdnlNodeIdFull, td::uint32>> servers);
  void try_create_connection();
  void update_addr_list(AdnlAddressList addr_list);
  void on_connection_fail(AdnlNodeIdShort causer);
};

}  // namespace adnl

}  // namespace ton
