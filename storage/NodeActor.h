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

    Copyright 2017-2020 Telegram Systems LLP
*/

#pragma once

#include "LoadSpeed.h"
#include "PartsHelper.h"
#include "PeerActor.h"
#include "Torrent.h"

#include "td/utils/Random.h"
#include "td/utils/Variant.h"

#include <map>
#include "db.h"

namespace ton {
class NodeActor : public td::actor::Actor {
 public:
  class NodeCallback {
   public:
    virtual ~NodeCallback() = default;
    virtual td::actor::ActorOwn<PeerActor> create_peer(PeerId self_id, PeerId peer_id,
                                                       std::shared_ptr<PeerState> state) = 0;
    virtual void get_peers(PeerId src, td::Promise<std::vector<PeerId>> peers) = 0;
    virtual void register_self(td::actor::ActorId<ton::NodeActor> self) = 0;
  };

  class Callback {
   public:
    virtual ~Callback() = default;
    virtual void on_completed() = 0;
    virtual void on_closed(ton::Torrent torrent) = 0;
  };

  struct PendingSetFilePriority {
    struct All {};
    td::Variant<All, size_t, std::string> file;
    td::uint8 priority;
  };
  struct DbInitialData {
    std::vector<PendingSetFilePriority> priorities;
    std::set<td::uint64> pieces_in_db;
  };

  NodeActor(PeerId self_id, ton::Torrent torrent, td::unique_ptr<Callback> callback,
            td::unique_ptr<NodeCallback> node_callback, std::shared_ptr<db::DbType> db, bool should_download = true);
  NodeActor(PeerId self_id, ton::Torrent torrent, td::unique_ptr<Callback> callback,
            td::unique_ptr<NodeCallback> node_callback, std::shared_ptr<db::DbType> db, bool should_download,
            DbInitialData db_initial_data);
  void start_peer(PeerId peer_id, td::Promise<td::actor::ActorId<PeerActor>> promise);

  struct NodeState {
    Torrent &torrent;
    bool active_download;
    double download_speed;
    double upload_speed;
    const std::vector<td::uint8> &file_priority;
  };
  void with_torrent(td::Promise<NodeState> promise) {
    // TODO: Upload speed
    promise.set_value(NodeState{torrent_, should_download_, download_.speed(), 0.0, file_priority_});
  }
  std::string get_stats_str();

  void set_should_download(bool should_download);

  void set_all_files_priority(td::uint8 priority, td::Promise<bool> promise);
  void set_file_priority_by_idx(size_t i, td::uint8 priority, td::Promise<bool> promise);
  void set_file_priority_by_name(std::string name, td::uint8 priority, td::Promise<bool> promise);

  void wait_for_completion(td::Promise<td::Unit> promise);

  static void load_from_db(std::shared_ptr<db::DbType> db, td::Bits256 hash, td::unique_ptr<Callback> callback,
                           td::unique_ptr<NodeCallback> node_callback,
                           td::Promise<td::actor::ActorOwn<NodeActor>> promise);
  static void cleanup_db(std::shared_ptr<db::DbType> db, td::Bits256 hash, td::Promise<td::Unit> promise);

 private:
  PeerId self_id_;
  ton::Torrent torrent_;
  std::shared_ptr<td::BufferSlice> torrent_info_str_;
  std::vector<td::uint8> file_priority_;
  td::unique_ptr<Callback> callback_;
  td::unique_ptr<NodeCallback> node_callback_;
  std::shared_ptr<db::DbType> db_;
  bool should_download_{false};

  class Notifier : public td::actor::Actor {
   public:
    Notifier(td::actor::ActorId<NodeActor> node, PeerId peer_id) : node_(std::move(node)), peer_id_(peer_id) {
    }

    void wake_up() override {
      send_closure(node_, &NodeActor::on_signal_from_peer, peer_id_);
    }

   private:
    td::actor::ActorId<NodeActor> node_;
    PeerId peer_id_;
  };

  struct Peer {
    td::actor::ActorOwn<PeerActor> actor;
    td::actor::ActorOwn<Notifier> notifier;
    std::shared_ptr<PeerState> state;
    PartsHelper::PeerToken peer_token;
  };

  std::map<PeerId, Peer> peers_;

  struct QueryId {
    PeerId peer;
    PartId part;

    auto key() const {
      return std::tie(peer, part);
    }
    bool operator<(const QueryId &other) const {
      return key() < other.key();
    }
  };

  struct PartsSet {
    struct Info {
      td::optional<PeerId> query_to_peer;
      bool ready{false};
    };
    size_t total_queries{0};
    std::vector<Info> parts;
  };

  PartsSet parts_;
  PartsHelper parts_helper_;
  std::vector<PartId> ready_parts_;
  LoadSpeed download_;

  td::Timestamp next_get_peers_at_;
  bool has_get_peers_{false};
  static constexpr double GET_PEER_RETRY_TIMEOUT = 5;
  static constexpr double GET_PEER_EACH = 5;

  bool is_completed_{false};
  std::vector<td::Promise<td::Unit>> wait_for_completion_;

  td::Timestamp will_upload_at_;

  std::vector<PendingSetFilePriority> pending_set_file_priority_;
  bool header_ready_ = false;
  std::map<std::string, size_t> file_name_to_idx_;
  std::set<td::uint64> pieces_in_db_;
  bool db_store_priorities_paused_ = false;
  td::int64 last_stored_meta_count_ = -1;
  td::Timestamp next_db_store_meta_at_ = td::Timestamp::now();

  void init_torrent();
  void init_torrent_header();
  void recheck_parts(Torrent::PartsRange range);

  void on_signal_from_peer(PeerId peer_id);

  void start_up() override;

  void loop() override;

  void tear_down() override;

  void loop_start_stop_peers();

  static constexpr size_t MAX_TOTAL_QUERIES = 20;
  static constexpr size_t MAX_PEER_TOTAL_QUERIES = 5;
  void loop_queries();
  void loop_get_peers();
  void got_peers(td::Result<std::vector<PeerId>> r_peers);
  void loop_peer(const PeerId &peer_id, Peer &peer);
  void on_part_ready(PartId part_id);

  void loop_will_upload();

  void got_torrent_info_str(td::BufferSlice data);

  void update_pieces_in_db(td::uint64 begin, td::uint64 end);

  void db_store_torrent();
  void db_store_priorities();
  void db_store_torrent_meta();
  void after_db_store_torrent_meta(td::Result<td::int64> R);
  void db_store_piece(td::uint64 i, std::string s);
  void db_erase_piece(td::uint64 i);
  void db_update_pieces_list();
};
}  // namespace ton
