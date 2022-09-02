/*
    This file is part of TON Blockchain source code.

    TON Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TON Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TON Blockchain.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "adnl-garlic-server.hpp"

#include "td/utils/port/signals.h"
#include "td/utils/OptionParser.h"
#include "td/utils/FileLog.h"
#include "td/utils/Random.h"
#include "td/utils/filesystem.h"
#include "td/utils/overloaded.h"

#include "auto/tl/ton_api_json.h"
#include "auto/tl/tonlib_api.hpp"

#include "common/errorcode.h"

#include "adnl/adnl.h"
#include "dht/dht.h"
#include "overlay/overlays.h"
#include "git.h"

#if TD_DARWIN || TD_LINUX
#include <unistd.h>
#endif

using namespace ton;

class GarlicServerRunner : public td::actor::Actor {
 public:
  GarlicServerRunner() = default;

  void set_global_config(std::string path) {
    global_config_ = std::move(path);
  }

  void set_addr(td::IPAddress addr) {
    addr_ = addr;
  }

  void set_adnl_addr(adnl::AdnlNodeIdShort id) {
    local_id_ = id;
  }

  void set_db_root(std::string db_root) {
    db_root_ = std::move(db_root);
  }

  td::Status load_global_config() {
    TRY_RESULT_PREFIX(conf_data, td::read_file(global_config_), "failed to read: ");
    TRY_RESULT_PREFIX(conf_json, td::json_decode(conf_data.as_slice()), "failed to parse json: ");

    ton_api::config_global conf;
    TRY_STATUS_PREFIX(ton_api::from_json(conf, conf_json.get_object()), "json does not fit TL scheme: ");

    if (!conf.dht_) {
      return td::Status::Error(ErrorCode::error, "does not contain [dht] section");
    }

    TRY_RESULT_PREFIX(dht, dht::Dht::create_global_config(std::move(conf.dht_)), "bad [dht] section: ");
    dht_config_ = std::move(dht);

    return td::Status::OK();
  }

  void run() {
    keyring_ = keyring::Keyring::create(db_root_ + "/keyring");
    {
      auto S = load_global_config();
      if (S.is_error()) {
        LOG(ERROR) << S;
        std::_Exit(2);
      }
    }
    if (local_id_.is_zero()) {
      auto pk = PrivateKey{privkeys::Ed25519::random()};
      auto pub = pk.compute_public_key();
      td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(pk), true, [](td::Unit) {});
      local_id_ = adnl::AdnlNodeIdShort{pub.compute_short_id()};
      run_cont(adnl::AdnlNodeIdFull{pub});
    } else {
      auto P =
          td::PromiseCreator::lambda([SelfId = actor_id(this), local_id = local_id_](td::Result<PublicKey> R) mutable {
            if (R.is_error()) {
              LOG(ERROR) << "No key for local id " << local_id << ": " << R.move_as_error();
              std::_Exit(2);
            } else {
              td::actor::send_closure(SelfId, &GarlicServerRunner::run_cont, adnl::AdnlNodeIdFull{R.move_as_ok()});
            }
          });
      td::actor::send_closure(keyring_, &keyring::Keyring::get_public_key, local_id_.pubkey_hash(), std::move(P));
    }
  }

  void run_cont(adnl::AdnlNodeIdFull local_id_full) {
    adnl_network_manager_ = adnl::AdnlNetworkManager::create(static_cast<td::uint16>(addr_.get_port()));
    adnl_ = adnl::Adnl::create(db_root_, keyring_.get());
    td::actor::send_closure(adnl_, &adnl::Adnl::register_network_manager, adnl_network_manager_.get());
    adnl::AdnlCategoryMask cat_mask;
    cat_mask[0] = true;
    td::actor::send_closure(adnl_network_manager_, &adnl::AdnlNetworkManager::add_self_addr, addr_, std::move(cat_mask),
                            0);

    adnl::AdnlAddressList addr_list;
    adnl::AdnlAddress x = adnl::AdnlAddressImpl::create(addr_);
    addr_list.add_addr(std::move(x));
    addr_list.set_version(static_cast<td::int32>(td::Clocks::system()));
    addr_list.set_reinit_date(adnl::Adnl::adnl_start_time());
    td::actor::send_closure(adnl_, &adnl::Adnl::add_id, local_id_full, addr_list, static_cast<td::uint8>(0));
    {
      auto pk = PrivateKey{privkeys::Ed25519::random()};
      auto pub = pk.compute_public_key();
      td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(pk), true, [](td::Unit) {});
      dht_id_ = adnl::AdnlNodeIdShort{pub.compute_short_id()};
      td::actor::send_closure(adnl_, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{pub}, addr_list,
                              static_cast<td::uint8>(0));
    }
    auto D = dht::Dht::create_client(dht_id_, "", dht_config_, keyring_.get(), adnl_.get());
    D.ensure();
    dht_ = D.move_as_ok();

    overlays_ = overlay::Overlays::create(db_root_, keyring_.get(), adnl_.get());

    garlic_server_ = td::actor::create_actor<adnl::AdnlGarlicServer>(
        "adnlgarlicserver", local_id_, keyring_.get(), adnl_.get(), adnl_network_manager_.get(), overlays_.get());
    LOG(INFO) << "Started ADNL garlic server on " << local_id_;
  }

 private:
  td::IPAddress addr_;
  std::string global_config_;
  std::shared_ptr<dht::DhtGlobalConfig> dht_config_;
  std::string db_root_ = ".";

  adnl::AdnlNodeIdShort local_id_ = adnl::AdnlNodeIdShort::zero();
  adnl::AdnlNodeIdShort dht_id_;

  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::AdnlNetworkManager> adnl_network_manager_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<dht::Dht> dht_;
  td::actor::ActorOwn<overlay::Overlays> overlays_;
  td::actor::ActorOwn<adnl::AdnlGarlicServer> garlic_server_;
};

int main(int argc, char *argv[]) {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);

  td::set_default_failure_signal_handler().ensure();

  td::actor::ActorOwn<GarlicServerRunner> x;
  td::unique_ptr<td::LogInterface> logger_;
  SCOPE_EXIT {
    td::log_interface = td::default_log_interface;
  };

  td::OptionParser p;
  p.set_description(
      "Adnl garlic server is a server that prioxies adnl packets and creates adnl tunnel midpoints.\n"
      "Clients use multime garlic servers to anonymously send and receive adnl messages.\n");
  p.add_option('v', "verbosity", "set verbosity level", [&](td::Slice arg) {
    int v = VERBOSITY_NAME(FATAL) + (td::to_integer<int>(arg));
    SET_VERBOSITY_LEVEL(v);
  });
  p.add_option('V', "version", "shows build information", [&]() {
    std::cout << "garlic-server-app build information: [ Commit: " << GitMetadata::CommitSHA1()
              << ", Date: " << GitMetadata::CommitDate() << "]\n";
    std::exit(0);
  });
  p.add_option('h', "help", "prints a help message", [&]() {
    char b[10240];
    td::StringBuilder sb(td::MutableSlice{b, 10000});
    sb << p;
    std::cout << sb.as_cslice().c_str();
    std::exit(2);
  });
  p.add_checked_option('a', "address", "local <ip>:<port> for adnl", [&](td::Slice arg) -> td::Status {
    td::IPAddress addr;
    TRY_STATUS(addr.init_host_port(arg.str()));
    td::actor::send_closure(x, &GarlicServerRunner::set_addr, addr);
    return td::Status::OK();
  });
  p.add_checked_option('A', "adnl", "server ADNL addr; random id if not set", [&](td::Slice arg) -> td::Status {
    TRY_RESULT(adnl, adnl::AdnlNodeIdShort::parse(arg));
    td::actor::send_closure(x, &GarlicServerRunner::set_adnl_addr, adnl);
    return td::Status::OK();
  });
  p.add_option('C', "global-config", "global TON configuration file",
               [&](td::Slice arg) { td::actor::send_closure(x, &GarlicServerRunner::set_global_config, arg.str()); });
  p.add_option('D', "db", "db root",
               [&](td::Slice arg) { td::actor::send_closure(x, &GarlicServerRunner::set_db_root, arg.str()); });
  p.add_option('d', "daemonize", "set SIGHUP", [&]() {
    td::set_signal_handler(td::SignalType::HangUp, [](int sig) {
#if TD_DARWIN || TD_LINUX
      close(0);
      setsid();
#endif
    }).ensure();
  });
  p.add_option('l', "logname", "log to file", [&](td::Slice fname) {
    logger_ = td::FileLog::create(fname.str()).move_as_ok();
    td::log_interface = logger_.get();
  });

  td::actor::Scheduler scheduler({7});

  scheduler.run_in_context([&] { x = td::actor::create_actor<GarlicServerRunner>("serverrunner"); });

  scheduler.run_in_context([&] { p.run(argc, argv).ensure(); });
  scheduler.run_in_context([&] { td::actor::send_closure(x, &GarlicServerRunner::run); });
  while (scheduler.run(1)) {
  }

  return 0;
}