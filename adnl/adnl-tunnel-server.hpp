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

#include "adnl-tunnel.h"
#include <map>

namespace ton {

namespace adnl {

class AdnlTunnelServer : public td::actor::Actor {
 public:
  explicit AdnlTunnelServer(AdnlNodeIdShort local_id, td::actor::ActorId<keyring::Keyring> keyring,
                            td::actor::ActorId<AdnlPeerTable> adnl)
      : local_id_(local_id), keyring_(std::move(keyring)), adnl_(std::move(adnl)) {
  }

  void start_up() override;
  void tear_down() override;

 private:
  AdnlNodeIdShort local_id_;
  td::actor::ActorId<keyring::Keyring> keyring_;
  td::actor::ActorId<AdnlPeerTable> adnl_;
  std::map<td::Bits256, td::actor::ActorOwn<AdnlInboundTunnelMidpoint>> tunnels_;

  void receive_message(AdnlNodeIdShort src, td::BufferSlice data);
  void receive_query(td::BufferSlice data, td::Promise<td::BufferSlice> promise);
};

}  // namespace adnl

}  // namespace ton
