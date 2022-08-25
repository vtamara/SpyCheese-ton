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

#include "adnl.h"
#include "adnl-peer-table.h"
#include "keys/encryptor.h"

namespace ton {

namespace adnl {

class AdnlHopServer : public td::actor::Actor {
 public:
  explicit AdnlHopServer(AdnlNodeIdShort local_id, td::actor::ActorId<keyring::Keyring> keyring,
                         td::actor::ActorId<Adnl> adnl, td::actor::ActorId<AdnlNetworkManager> network_manager)
      : local_id_(local_id)
      , keyring_(std::move(keyring))
      , adnl_(std::move(adnl))
      , network_manager_(std::move(network_manager)) {
  }

  void start_up() override;
  void tear_down() override;

 private:
  AdnlNodeIdShort local_id_;
  td::actor::ActorId<keyring::Keyring> keyring_;
  td::actor::ActorId<Adnl> adnl_;
  td::actor::ActorId<AdnlNetworkManager> network_manager_;

  void receive_message(AdnlNodeIdShort src, td::BufferSlice data);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_hop_encryptedMessage& obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_hop_forwardToUdp& obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_hop_forwardToHop& obj);
};

class AdnlHopClient : public td::actor::Actor {
 public:
  AdnlHopClient(AdnlNodeIdShort local_id, std::vector<AdnlNodeIdFull> hops, td::actor::ActorId<Adnl> adnl)
      : local_id_(local_id), adnl_(std::move(adnl)) {
    for (const AdnlNodeIdFull& id : hops) {
      hops_.push_back(id.compute_short_id());
      auto E = id.pubkey().create_encryptor();
      E.ensure();
      encryptors_.push_back(E.move_as_ok());
    }
  }

  void send_packet(AdnlNodeIdShort src, td::IPAddress dst_ip, td::BufferSlice data);

 private:
  AdnlNodeIdShort local_id_;
  std::vector<AdnlNodeIdShort> hops_;
  std::vector<std::unique_ptr<Encryptor>> encryptors_;
  td::actor::ActorId<Adnl> adnl_;
};

}  // namespace adnl

}  // namespace ton
