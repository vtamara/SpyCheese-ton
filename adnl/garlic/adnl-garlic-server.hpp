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
#include "adnl/adnl-peer-table.h"
#include "keys/encryptor.h"
#include "adnl/utils.hpp"
#include "overlay/overlays.h"

namespace ton {

namespace adnl {

class AdnlGarlicServer : public td::actor::Actor {
 public:
  explicit AdnlGarlicServer(AdnlNodeIdShort local_id, td::actor::ActorId<keyring::Keyring> keyring,
                            td::actor::ActorId<Adnl> adnl, td::actor::ActorId<AdnlNetworkManager> network_manager,
                            td::actor::ActorId<overlay::Overlays> overlays)
      : local_id_(local_id)
      , keyring_(std::move(keyring))
      , adnl_(std::move(adnl))
      , network_manager_(std::move(network_manager))
      , overlays_(std::move(overlays)) {
  }

  void start_up() override;
  void tear_down() override;
  void alarm() override;

 private:
  AdnlNodeIdShort local_id_;
  td::actor::ActorId<keyring::Keyring> keyring_;
  td::actor::ActorId<Adnl> adnl_;
  td::actor::ActorId<AdnlNetworkManager> network_manager_;
  td::actor::ActorId<overlay::Overlays> overlays_;

  overlay::OverlayIdFull overlay_id_full_;
  overlay::OverlayIdShort overlay_id_;

  struct TunnelMidpoint {
    td::actor::ActorOwn<AdnlInboundTunnelMidpoint> actor;
    AdnlSubscribeGuard guard;
    td::Timestamp ttl;
  };
  std::map<td::Bits256, TunnelMidpoint> tunnels_;
  struct GarlicChannel {
    std::unique_ptr<Decryptor> decryptor;
    td::Timestamp ttl;
  };
  std::map<td::Bits256, GarlicChannel> garlic_channels_;

  void receive_message(AdnlNodeIdShort src, td::BufferSlice data);
  void process_message(AdnlNodeIdShort src, tl_object_ptr<ton_api::adnl_garlic_Message> obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_encryptedMessage& obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_encryptedMessageChannel& obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_multipleMessages& obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_forwardToUdp& obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_forwardToNext& obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_forwardToNextChannel& obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_createTunnelMidpoint& obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_createChannel& obj);
  void process_message(AdnlNodeIdShort src, ton_api::adnl_garlic_ping& obj);

  void update_tunnel_ttl(td::Bits256 id);
};

}  // namespace adnl

}  // namespace ton
