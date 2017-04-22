// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P11NET_P11NET_FACTORY_IMPL_H_
#define P11NET_P11NET_FACTORY_IMPL_H_

#include "p11net_factory.h"

#include <base/macros.h>

namespace p11net {

class P11NetFactoryImpl : public P11NetFactory,
                         public std::enable_shared_from_this<P11NetFactoryImpl> {
 public:
  P11NetFactoryImpl() {}
  virtual ~P11NetFactoryImpl() {}
  virtual Session* CreateSession(int slot_id,
                                 std::shared_ptr<ObjectPool> token_object_pool,
                                 std::shared_ptr<NetUtility> net_utility,
                                 std::shared_ptr<HandleGenerator> handle_generator,
                                 bool is_read_only);
  virtual ObjectPool* CreateObjectPool(std::shared_ptr<HandleGenerator> handle_generator,
                                       std::unique_ptr<ObjectStore> store);
  virtual ObjectStore* CreateObjectStore(const base::FilePath& file_name);
  virtual Object* CreateObject();
  virtual ObjectPolicy* CreateObjectPolicy(CK_OBJECT_CLASS type);
  virtual NetUtility* CreateNetUtility(std::shared_ptr<ObjectPool> token_object_pool);

 private:
  DISALLOW_COPY_AND_ASSIGN(P11NetFactoryImpl);
};

}  // namespace p11net

#endif  // P11NET_P11NET_FACTORY_IMPL_H_
