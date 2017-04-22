// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_OBJECT_POLICY_PRIVATE_KEY_H_
#define P11NET_OBJECT_POLICY_PRIVATE_KEY_H_

#include "object_policy_key.h"

namespace p11net {

// Enforces common policies for private key objects (CKO_PRIVATE_KEY).
class ObjectPolicyPrivateKey : public ObjectPolicyKey {
 public:
  ObjectPolicyPrivateKey();
  virtual ~ObjectPolicyPrivateKey();
  virtual bool IsObjectComplete();
  virtual void SetDefaultAttributes();
};

}  // namespace p11net

#endif  // P11NET_OBJECT_POLICY_PRIVATE_KEY_H_
