// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_OBJECT_POLICY_PUBLIC_KEY_H_
#define P11NET_OBJECT_POLICY_PUBLIC_KEY_H_

#include "object_policy_key.h"

namespace p11net {

// Enforces common policies for public key objects (CKO_PUBLIC_KEY).
class ObjectPolicyPublicKey : public ObjectPolicyKey {
 public:
  ObjectPolicyPublicKey();
  virtual ~ObjectPolicyPublicKey();
  virtual void SetDefaultAttributes();
};

}  // namespace p11net

#endif  // P11NET_OBJECT_POLICY_PUBLIC_KEY_H_
