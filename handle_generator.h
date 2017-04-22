// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_HANDLE_GENERATOR_H_
#define P11NET_HANDLE_GENERATOR_H_

namespace p11net {

// A HandleGenerator simply generates unique handles.
class HandleGenerator {
 public:
  virtual ~HandleGenerator() {}
  virtual int CreateHandle() = 0;
};

}  // namespace p11net

#endif  // P11NET_HANDLE_GENERATOR_H_
