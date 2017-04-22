// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_P11NET_FACTORY_H_
#define P11NET_P11NET_FACTORY_H_

#include <string>

#include <base/files/file_path.h>

#include "pkcs11/cryptoki.h"

namespace p11net {

class HandleGenerator;
class Object;
class ObjectImporter;
class ObjectPolicy;
class ObjectPool;
class ObjectStore;
class Session;
class NetUtility;

// P11NetFactory is a factory for a number of interfaces in the P11Net
// environment. Having this factory allows object implementations to be
// decoupled and allows the creation of mock objects.
class P11NetFactory {
 public:
  virtual ~P11NetFactory() {}
  virtual Session* CreateSession(int slot_id,
                                 std::shared_ptr<ObjectPool> token_object_pool,
                                 std::shared_ptr<NetUtility> net_utility,
                                 std::shared_ptr<HandleGenerator> handle_generator,
                                 bool is_read_only) = 0;
  virtual ObjectPool* CreateObjectPool(std::shared_ptr<HandleGenerator> handle_generator,
                                       std::unique_ptr<ObjectStore> store) = 0;
  virtual ObjectStore* CreateObjectStore(const base::FilePath& file_name) = 0;
  virtual Object* CreateObject() = 0;
  virtual ObjectPolicy* CreateObjectPolicy(CK_OBJECT_CLASS type) = 0;
  virtual NetUtility* CreateNetUtility(std::shared_ptr<ObjectPool> token_object_pool) = 0;
};

}  // namespace p11net

#endif  // P11NET_P11NET_FACTORY_H_
