// Copyright 2015 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup.hpp>

namespace logging {

void Init() {
  static bool initialized = false;
  if (initialized) return;
  initialized = true;
  boost::log::add_common_attributes();
  boost::log::register_simple_formatter_factory<
    boost::log::trivial::severity_level, char>("Severity");
  boost::log::add_console_log(
    std::clog,
    boost::log::keywords::format =
      "p11net|%TimeStamp%|%Severity%|%Message%"
 );
  // boost::log::core::get()->set_filter
  // (
  //     boost::log::trivial::severity >= boost::log::trivial::trace
  // );
  VLOG(1) << "Logging initialized.";
}

}  // namespace logging
