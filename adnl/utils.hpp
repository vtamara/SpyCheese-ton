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

#include "td/utils/buffer.h"
#include "td/utils/misc.h"
#include "td/utils/crypto.h"
#include "td/utils/format.h"
#include "td/utils/base64.h"
#include "tl-utils/tl-utils.hpp"

#include "common/errorcode.h"
#include "common/checksum.h"
#include "adnl-node-id.hpp"
#include "common/status.h"
#include "adnl-node.h"
#include "adnl-address-list.hpp"
#include "adnl.h"

namespace ton {

namespace adnl {

class AdnlSubscribeGuard {
 public:
  AdnlSubscribeGuard() = default;

  AdnlSubscribeGuard(td::actor::ActorId<Adnl> adnl, AdnlNodeIdShort id, std::string prefix,
                     std::unique_ptr<Adnl::Callback> cb)
      : adnl_(std::move(adnl)), id_(id), prefix_(std::move(prefix)) {
    td::actor::send_closure(adnl_, &Adnl::subscribe, id_, prefix_, std::move(cb));
  }

  AdnlSubscribeGuard(AdnlSubscribeGuard&& b) : adnl_(std::move(b.adnl_)), id_(b.id_), prefix_(std::move(b.prefix_)) {
    b.adnl_ = {};
  }

  AdnlSubscribeGuard(const AdnlSubscribeGuard&) = delete;

  AdnlSubscribeGuard& operator =(AdnlSubscribeGuard b) {
    std::swap(adnl_, b.adnl_);
    std::swap(id_, b.id_);
    std::swap(prefix_, b.prefix_);
    return *this;
  }

  ~AdnlSubscribeGuard() {
    if (!adnl_.empty()) {
      td::actor::send_closure(adnl_, &Adnl::unsubscribe, id_, std::move(prefix_));
    }
  }

 private:
  td::actor::ActorId<Adnl> adnl_;
  AdnlNodeIdShort id_;
  std::string prefix_;
};

}  // namespace adnl

}  // namespace ton
