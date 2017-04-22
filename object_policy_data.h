// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_OBJECT_POLICY_DATA_H_
#define P11NET_OBJECT_POLICY_DATA_H_

#include "object_policy_common.h"

namespace p11net {

// Enforces policies for data objects (CKO_DATA).
class ObjectPolicyData : public ObjectPolicyCommon {
 public:
  ObjectPolicyData();
  virtual ~ObjectPolicyData();
  virtual void SetDefaultAttributes();
};

}  // namespace p11net

#endif  // P11NET_OBJECT_POLICY_DATA_H_
