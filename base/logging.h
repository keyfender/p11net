// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_LOGGING_H_
#define P11NET_LOGGING_H_

#include <errno.h>   // for errno
#include <string.h>  // for strerror

#include <boost/log/trivial.hpp>

namespace logging {

// Sets the log level. Anything at or above this level will be written to the
// log file/displayed to the user (if applicable). Anything below this level
// will be silently ignored. The log level defaults to 0 (everything is logged
// up to level INFO) if this function is not called.
// Note that log messages for VLOG(x) are logged at level -x, so setting
// the min log level to negative values enables verbose logging.
void Init();

}  // namespace logging

// These macros are for LOG() and related logging commands.
#define LOG(level) LOG_ ## level << " "
#define PLOG(level) LOG_ ## level << "Error: " << strerror(errno) << "| "
#define VLOG(level) LOG_DEBUG << __FILE__ << ":" << __LINE__ << "| "

#define LOG_TRACE BOOST_LOG_TRIVIAL(trace)
#define LOG_DEBUG BOOST_LOG_TRIVIAL(debug)
#define LOG_INFO BOOST_LOG_TRIVIAL(info)
#define LOG_WARNING BOOST_LOG_TRIVIAL(warning)
#define LOG_ERROR BOOST_LOG_TRIVIAL(error)
#define LOG_FATAL BOOST_LOG_TRIVIAL(fatal)

// Some macros from libbase that we use.
#define CHECK(x) if (!(x)) LOG(FATAL) << #x
#define CHECK_GT(x, y) if (!(x > y)) LOG(FATAL) << #x << " > " << #y << "failed"
#define CHECK_LT(x, y) if (!(x < y)) LOG(FATAL) << #x << " < " << #y << "failed"
#define CHECK_GE(x, y) if (!(x >= y)) LOG(FATAL) << #x << " >= " << #y \
                                                 << "failed"
#define CHECK_LE(x, y) if (!(x <= y)) LOG(FATAL) << #x << " <= " << #y \
                                                 << "failed"
#define CHECK_NE(x, y) if (!(x != y)) LOG(FATAL) << #x << " != " << #y \
                                                 << "failed"
#define CHECK_EQ(x, y) if (!(x == y)) LOG(FATAL) << #x << " == " << #y \
                                                 << "failed"

#endif  // P11NET_LOGGING_H_
