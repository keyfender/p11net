// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_OBJECT_POLICY_CERT_H_
#define P11NET_OBJECT_POLICY_CERT_H_

#include "object_policy_common.h"

namespace p11net {

// Enforces policies for certificate objects (CKO_CERTIFICATE).
class ObjectPolicyCert : public ObjectPolicyCommon {
 public:
  ObjectPolicyCert();
  virtual ~ObjectPolicyCert();
  virtual bool IsObjectComplete();
  virtual void SetDefaultAttributes();
};

}  // namespace p11net

#endif  // P11NET_OBJECT_POLICY_CERT_H_
