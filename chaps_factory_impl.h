// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_CHAPS_FACTORY_IMPL_H_
#define CHAPS_CHAPS_FACTORY_IMPL_H_

#include "chaps_factory.h"

#include <base/macros.h>

namespace chaps {

class ChapsFactoryImpl : public ChapsFactory,
                         public std::enable_shared_from_this<ChapsFactoryImpl> {
 public:
  ChapsFactoryImpl() {}
  virtual ~ChapsFactoryImpl() {}
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
  DISALLOW_COPY_AND_ASSIGN(ChapsFactoryImpl);
};

}  // namespace chaps

#endif  // CHAPS_CHAPS_FACTORY_IMPL_H_
