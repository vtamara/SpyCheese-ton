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

    In addition, as a special exception, the copyright holders give permission
    to link the code of portions of this program with the OpenSSL library.
    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the file(s),
    but you are not obligated to do so. If you do not wish to do so, delete this
    exception statement from your version. If you delete this exception statement
    from all source files in the program, then also delete it here.
*/
#include "TonlibClient.h"

static td::Result<ton::adnl::AdnlNodeIdShort> select_server_adnl_id(const std::string& config_str) {
  TRY_RESULT(config, tonlib::Config::parse(config_str));
  if (config.lite_clients.empty()) {
    return td::Status::Error("No lite servers in config");
  }
  const auto& client = config.lite_clients[td::Random::fast(0, td::narrow_cast<int>(config.lite_clients.size()) - 1)];
  return client.adnl_id.compute_short_id();
}

TonlibClient::TonlibClient(ton::tl_object_ptr<tonlib_api::options> options) : options_(std::move(options)) {
}

TonlibClient::TonlibClient(ton::tl_object_ptr<tonlib_api::options> options,
                           td::actor::ActorId<ton::adnl::AdnlSenderInterface> sender,
                           ton::adnl::AdnlNodeIdShort local_id)
    : options_(std::move(options)), sender_(std::move(sender)), local_id_(local_id) {
  options_->config_->use_callbacks_for_network_ = true;
}

void TonlibClient::start_up() {
  class Cb : public tonlib::TonlibCallback {
   public:
    explicit Cb(td::actor::ActorId<TonlibClient> self_id) : self_id_(self_id) {
    }
    void on_result(std::uint64_t id, tonlib_api::object_ptr<tonlib_api::Object> result) override {
      td::actor::send_closure(self_id_, &TonlibClient::receive_request_result, id, std::move(result));
    }
    void on_error(std::uint64_t id, tonlib_api::object_ptr<tonlib_api::error> error) override {
      td::actor::send_closure(self_id_, &TonlibClient::receive_request_result, id,
                              td::Status::Error(error->code_, std::move(error->message_)));
    }

   private:
    td::actor::ActorId<TonlibClient> self_id_;
  };

  if (!sender_.empty()) {
    auto R = select_server_adnl_id(options_->config_->config_);
    if (R.is_error()) {
      LOG(ERROR) << "Failed to select liteserver: " << R.move_as_error();
    } else {
      custom_server_id_ = R.move_as_ok();
    }
  }

  tonlib_client_ = td::actor::create_actor<tonlib::TonlibClient>("tonlibclient", td::make_unique<Cb>(actor_id(this)));
  auto init = tonlib_api::make_object<tonlib_api::init>(std::move(options_));
  auto P = td::PromiseCreator::lambda([](td::Result<tonlib_api::object_ptr<tonlib_api::Object>> R) mutable {
    R.ensure();
  });
  send_request(std::move(init), std::move(P));
}

void TonlibClient::send_request(tonlib_api::object_ptr<tonlib_api::Function> obj,
                                td::Promise<tonlib_api::object_ptr<tonlib_api::Object>> promise) {
  auto id = next_request_id_++;
  CHECK(requests_.emplace(id, std::move(promise)).second);
  td::actor::send_closure(tonlib_client_, &tonlib::TonlibClient::request, id, std::move(obj));
}

void TonlibClient::receive_request_result(td::uint64 id, td::Result<tonlib_api::object_ptr<tonlib_api::Object>> R) {
  if (id == 0) {
    if (R.is_error()) {
      LOG(WARNING) << "Tonlib error: " << R.move_as_error();
      return;
    }
    auto object = R.move_as_ok();
    if (object->get_id() == tonlib_api::updateSendLiteServerQuery::ID) {
      auto update = tonlib_api::move_object_as<tonlib_api::updateSendLiteServerQuery>(std::move(object));
      if (sender_.empty() || custom_server_id_.is_zero()) {
        receive_adnl_result(update->id_, td::Status::Error("Custom sender is invalid"));
      } else {
        td::actor::send_closure(
            sender_, &ton::adnl::AdnlSenderInterface::send_query, local_id_, custom_server_id_, "query",
            [SelfId = actor_id(this), id = update->id_](td::Result<td::BufferSlice> R) {
              td::actor::send_closure(SelfId, &TonlibClient::receive_adnl_result, id, std::move(R));
            },
            td::Timestamp::in(10.0), td::BufferSlice(update->data_));
      }
      return;
    }
    return;
  }
  auto it = requests_.find(id);
  CHECK(it != requests_.end());
  auto promise = std::move(it->second);
  requests_.erase(it);
  promise.set_result(std::move(R));
}

void TonlibClient::receive_adnl_result(td::int64 id, td::Result<td::BufferSlice> R) {
  tonlib_api::object_ptr<tonlib_api::Function> object;
  if (R.is_ok()) {
    object = tonlib_api::make_object<tonlib_api::onLiteServerQueryResult>(id, R.move_as_ok().as_slice().str());
  } else {
    object = tonlib_api::make_object<tonlib_api::onLiteServerQueryError>(
        id, tonlib_api::make_object<tonlib_api::error>(R.error().code(), R.error().message().str()));
  }
  send_request(std::move(object), [](td::Result<tonlib_api::object_ptr<tonlib_api::Object>>){});
}
