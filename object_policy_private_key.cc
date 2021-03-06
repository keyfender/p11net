// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "object_policy_private_key.h"

#include <base/logging.h>
#include <base/macros.h>

#include "p11net.h"
#include "p11net_utility.h"

namespace p11net {

// Read policy list as follows:
//   {attribute, sensitive, read-only {create, copy, modify}, required}
// sensitive - True if attribute cannot be read.
// read-only.create - True if attribute cannot be set with C_CreateObject.
// read-only.copy - True if attribute cannot be set with C_CopyObject.
// read-only.modify - True if attribute cannot be set with C_SetAttributeValue.
// required - True if attribute is required for a valid object.
static const AttributePolicy kPrivateKeyPolicies[] = {
  {CKA_ALWAYS_SENSITIVE, false, {true, true, true}, false},
  {CKA_NEVER_EXTRACTABLE, false, {true, true, true}, false},
  {CKA_UNWRAP_TEMPLATE, false, {false, false, true}, false},
  {CKA_ALWAYS_AUTHENTICATE, false, {false, false, true}, false},
  // RSA-specific attributes.
  {CKA_MODULUS, false, {false, false, true}, true},
  {CKA_PUBLIC_EXPONENT, false, {false, false, true}, true},
  {CKA_PRIVATE_EXPONENT, true, {false, false, true}, false},
  {CKA_PRIME_1, true, {false, false, true}, false},
  {CKA_PRIME_2, true, {false, false, true}, false},
  {CKA_EXPONENT_1, true, {false, false, true}, false},
  {CKA_EXPONENT_2, true, {false, false, true}, false},
  {CKA_COEFFICIENT, true, {false, false, true}, false},
  {kKeyBlobAttribute, true, {false, true, true}, false},
  {kAuthDataAttribute, true, {false, true, true}, false},
  {kKeyLocationAttribute, true, {false, true, true}, false},
};

ObjectPolicyPrivateKey::ObjectPolicyPrivateKey() {
  AddPolicies(kPrivateKeyPolicies, arraysize(kPrivateKeyPolicies));
}

ObjectPolicyPrivateKey::~ObjectPolicyPrivateKey() {}

bool ObjectPolicyPrivateKey::IsObjectComplete() {
  if (!ObjectPolicyCommon::IsObjectComplete())
    return false;
  // Either a private exponent or a key location must exist.
  if (!object_->IsAttributePresent(CKA_PRIVATE_EXPONENT) &&
      !object_->IsAttributePresent(kKeyLocationAttribute)) {
    LOG(ERROR) << "Private key attributes are required.";
    return false;
  }
  return true;
}

void ObjectPolicyPrivateKey::SetDefaultAttributes() {
  ObjectPolicyKey::SetDefaultAttributes();
  if (!object_->IsAttributePresent(CKA_SUBJECT))
    object_->SetAttributeString(CKA_SUBJECT, "");
  if (!object_->IsAttributePresent(CKA_SENSITIVE))
    object_->SetAttributeBool(CKA_SENSITIVE, true);
  if (!object_->IsAttributePresent(CKA_DECRYPT))
    object_->SetAttributeBool(CKA_DECRYPT, false);
  if (!object_->IsAttributePresent(CKA_SIGN))
    object_->SetAttributeBool(CKA_SIGN, false);
  if (!object_->IsAttributePresent(CKA_SIGN_RECOVER))
    object_->SetAttributeBool(CKA_SIGN_RECOVER, false);
  if (!object_->IsAttributePresent(CKA_UNWRAP))
    object_->SetAttributeBool(CKA_UNWRAP, false);
  if (!object_->IsAttributePresent(CKA_EXTRACTABLE))
    object_->SetAttributeBool(CKA_EXTRACTABLE, false);
  if (!object_->IsAttributePresent(CKA_WRAP_WITH_TRUSTED))
    object_->SetAttributeBool(CKA_WRAP_WITH_TRUSTED, false);
  if (!object_->IsAttributePresent(CKA_ALWAYS_AUTHENTICATE))
    object_->SetAttributeBool(CKA_ALWAYS_AUTHENTICATE, false);
  if (object_->GetStage() == kCreate) {
    CK_ULONG keygen_mechanism = object_->GetAttributeInt(
        CKA_KEY_GEN_MECHANISM, static_cast<int>(CK_UNAVAILABLE_INFORMATION));
    bool keygen_known = (keygen_mechanism != CK_UNAVAILABLE_INFORMATION);
    if (keygen_known && object_->GetAttributeBool(CKA_SENSITIVE, false))
      object_->SetAttributeBool(CKA_ALWAYS_SENSITIVE, true);
    else
      object_->SetAttributeBool(CKA_ALWAYS_SENSITIVE, false);
    if (keygen_known && !object_->GetAttributeBool(CKA_EXTRACTABLE, true))
      object_->SetAttributeBool(CKA_NEVER_EXTRACTABLE, true);
    else
      object_->SetAttributeBool(CKA_NEVER_EXTRACTABLE, false);
  }
}

}  // namespace p11net
