// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_OBJECT_POLICY_H_
#define P11NET_OBJECT_POLICY_H_

#include <string>

#include "pkcs11/cryptoki.h"

namespace p11net {

class Object;

// ObjectPolicy encapsulates policies for a PKCS #11 object.
class ObjectPolicy {
 public:
  virtual ~ObjectPolicy() {}
  virtual void Init(Object* object) = 0;
  virtual bool IsReadAllowed(CK_ATTRIBUTE_TYPE type) = 0;
  virtual bool IsModifyAllowed(CK_ATTRIBUTE_TYPE type,
                               const std::string& value) = 0;
  virtual bool IsObjectComplete() = 0;
  virtual void SetDefaultAttributes() = 0;
};

}  // namespace p11net

#endif  // P11NET_OBJECT_POLICY_H_
