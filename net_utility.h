// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_NET_UTILITY_H_
#define P11NET_NET_UTILITY_H_

#include <string>
#include <boost/optional.hpp>

namespace p11net {

// NetUtility is a high-level interface to NetHSM services. In practice, only a
// single instance of this class is necessary to provide network services across
// multiple logical tokens and sessions.
class NetUtility {
 public:
  virtual ~NetUtility() {}

  // Performs initialization tasks.
  // This may be called multiple times.
  // Returns true on success.
  virtual bool Init() = 0;

  virtual bool LoadKeys(const std::string& key_id) = 0;

  // Retrieves the public components of an RSA key pair. Returns true on
  // success.
  // virtual bool GetPublicKey(int key_handle,
  //                           std::string* public_exponent,
  //                           std::string* modulus) = 0;

  virtual boost::optional<std::string> Decrypt(const std::string& key_id,
                                               const std::string& input) = 0;

  virtual boost::optional<std::string> Sign(const std::string& key_id,
                                            const std::string& input) = 0;
};

}  // namespace p11net

#endif  // P11NET_TPM_UTILITY_H_
