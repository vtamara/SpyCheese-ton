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

namespace ton {

namespace adnl {

class AdnlGarlicManager : public AdnlNetworkManager::CustomSender {
 public:
  AdnlGarlicManager(AdnlNodeIdShort local_id, td::uint8 adnl_cat, td::actor::ActorId<Adnl> adnl,
                    td::actor::ActorId<keyring::Keyring> keyring, std::shared_ptr<dht::DhtGlobalConfig> dht_config);

  void start_up() override;
  void send_packet(AdnlNodeIdShort src, td::IPAddress dst_ip, td::BufferSlice data) override;
  void add_server(AdnlNodeIdFull server);
  void init_connection(size_t chain_length, td::Promise<td::Unit> promise);

  void create_secret_id(AdnlNodeIdFull id, td::Promise<td::Unit> promise);

  void alarm() override;

 private:
  AdnlNodeIdShort local_id_;
  td::uint8 adnl_cat_;
  td::actor::ActorId<Adnl> adnl_;
  td::actor::ActorId<keyring::Keyring> keyring_;
  std::shared_ptr<dht::DhtGlobalConfig> dht_config_;

  struct Server {
    AdnlNodeIdFull id_full;
  };
  std::map<AdnlNodeIdShort, Server> servers_;
  std::vector<AdnlNodeIdShort> servers_vec_;

  struct Connection {
    std::vector<AdnlNodeIdShort> chain;
    std::vector<std::unique_ptr<Encryptor>> encryptors;
    td::actor::ActorOwn<AdnlInboundTunnelEndpoint> endpoint;
    std::vector<PublicKey> pubkeys;
    AdnlSubscribeGuard guard;
    AdnlAddressList addr_list;

    bool ready = false;
    td::Promise<td::Unit> ready_promise;
    td::Bits256 init_nonce;
    td::Timestamp ready_ttl;
  };
  std::unique_ptr<Connection> connection_;

  struct SecretId {
    AdnlNodeIdFull id_full;
  };
  std::map<AdnlNodeIdShort, SecretId> secret_ids_;
  td::actor::ActorOwn<dht::Dht> secret_dht_node_;

  bool use_secret_dht() const {
    return dht_config_ != nullptr;
  }
  td::uint32 local_id_mode() const {
    return (td::uint32)AdnlLocalIdMode::send_ignore_remote_addr |
           (use_secret_dht() ? (td::uint32)AdnlLocalIdMode::custom_dht_node : 0);
  }

  void update_addr_lists();

  void receive_custom_message(size_t sender_id, td::BufferSlice data);

  void wrap_send_message(const Connection& connection, std::vector<tl_object_ptr<ton_api::adnl_garlic_Message>> msgs);
  void wrap_send_message(const Connection& connection, tl_object_ptr<ton_api::adnl_garlic_Message> msg);
};

}  // namespace adnl

}  // namespace ton
