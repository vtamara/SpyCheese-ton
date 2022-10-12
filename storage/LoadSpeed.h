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

#include "td/utils/StringBuilder.h"
#include "td/utils/Time.h"
#include "td/utils/VectorQueue.h"
#include <atomic>

namespace ton {
// Thread-safe: allows one writer and multiple readers
class LoadSpeed {
 public:
  void add(std::size_t size, td::Timestamp now);
  double speed(td::Timestamp now = td::Timestamp::now()) const;
  friend td::StringBuilder &operator<<(td::StringBuilder &sb, const LoadSpeed &speed);

 private:
  struct Event {
    std::size_t size;
    td::Timestamp at;
  };
  mutable td::VectorQueue<Event> events_;
  mutable std::size_t total_size_{0};
  std::atomic<double> speed_{0.0};

  double duration() const;
  void update(td::Timestamp now) const;
};
}  // namespace ton
