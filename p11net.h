// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_P11NET_H_
#define P11NET_P11NET_H_

#include <map>
#include <vector>

#include "pkcs11/cryptoki.h"

namespace p11net {

extern const char* kP11NetServicePath;
extern const char* kP11NetServiceName;
extern const size_t kTokenLabelSize;
extern const CK_ATTRIBUTE_TYPE kKeyBlobAttribute;
extern const CK_ATTRIBUTE_TYPE kAuthDataAttribute;
extern const CK_ATTRIBUTE_TYPE kLegacyAttribute;
extern const CK_ATTRIBUTE_TYPE kKeyLocationAttribute;

}  // namespace p11net

#endif  // P11NET_P11NET_H_
