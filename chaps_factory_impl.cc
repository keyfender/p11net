// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps_factory_impl.h"

#include <string>

#include <base/logging.h>

#include "object_impl.h"
#include "object_policy_cert.h"
#include "object_policy_common.h"
#include "object_policy_data.h"
#include "object_policy_private_key.h"
#include "object_policy_public_key.h"
#include "object_policy_secret_key.h"
#include "object_pool_impl.h"
#include "object_store_fake.h"
#include "object_store_impl.h"
#include "session_impl.h"
#include "net_utility_impl.h"

using base::FilePath;
using std::string;

namespace chaps {

Session* ChapsFactoryImpl::CreateSession(int slot_id,
                                         std::shared_ptr<ObjectPool> token_object_pool,
                                         std::shared_ptr<NetUtility> net_utility,
                                         std::shared_ptr<HandleGenerator> handle_generator,
                                         bool is_read_only) {
  return new SessionImpl(slot_id,
                         token_object_pool,
                         net_utility,
                         shared_from_this(),
                         handle_generator,
                         is_read_only);
}

ObjectPool* ChapsFactoryImpl::CreateObjectPool(
    std::shared_ptr<HandleGenerator> handle_generator,
    std::unique_ptr<ObjectStore> object_store) {
  std::unique_ptr<ObjectPoolImpl> pool(new ObjectPoolImpl(shared_from_this(),
                                                     handle_generator,
                                                     std::move(object_store)));
  CHECK(pool.get());
  if (!pool->Init())
    return NULL;
  return pool.release();
}

ObjectStore* ChapsFactoryImpl::CreateObjectStore(const FilePath& file_name) {
  std::unique_ptr<ObjectStoreImpl> store(new ObjectStoreImpl());
  if (!store->Init(file_name)) {
    // The approach here is to limp along without a persistent object store so
    // crypto services do not become unavailable. The side-effect is that all
    // objects will disappear when the token is removed (e.g. at logout).
    LOG(WARNING)
        << "Object store initialization failed, proceeding with fake store.";
    return new ObjectStoreFake();
  }
  return store.release();
}

Object* ChapsFactoryImpl::CreateObject() {
  return new ObjectImpl(this);
}

ObjectPolicy* ChapsFactoryImpl::CreateObjectPolicy(CK_OBJECT_CLASS type) {
  switch (type) {
    case CKO_DATA:
      return new ObjectPolicyData();
    case CKO_CERTIFICATE:
      return new ObjectPolicyCert();
    case CKO_PUBLIC_KEY:
      return new ObjectPolicyPublicKey();
    case CKO_PRIVATE_KEY:
      return new ObjectPolicyPrivateKey();
    case CKO_SECRET_KEY:
      return new ObjectPolicySecretKey();
  }
  return new ObjectPolicyCommon();
}

NetUtility* ChapsFactoryImpl::CreateNetUtility(
  std::shared_ptr<ObjectPool> token_object_pool
) {
  return new NetUtilityImpl(token_object_pool,
                            shared_from_this());
}

}  // namespace chaps
