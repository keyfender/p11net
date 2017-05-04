// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "slot_manager_impl.h"

#include <string.h>

#include <limits>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <boost/thread/lock_guard.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "p11net_utility.h"
#include "isolate.h"
#include "object_store.h"
#include "session.h"
#include "net_utility.h"
#include "pkcs11/cryptoki.h"

using brillo::SecureBlob;
using std::map;
using std::string;
using std::shared_ptr;
using std::vector;

namespace p11net {

namespace {

// I18N Note: The descriptive strings are needed for PKCS #11 compliance but
// they should not appear on any UI.
const CK_VERSION kDefaultVersion = {1, 0};
const char kManufacturerID[] = "NitroKey";
const CK_ULONG kMaxPinLen = 127;
const CK_ULONG kMinPinLen = 6;
const char kSlotDescription[] = "NetHSM Slot";
// const boost::filesystem::path::CharType kSystemTokenPath[] =
//     FILE_PATH_LITERAL("/Users/sanders/.p11net");
const char kSystemTokenAuthData[] = "000000";
const char kSystemTokenLabel[] = "System NetHSM Token";
const char kTokenLabel[] = "User-Specific NetHSM Token";
const char kTokenModel[] = "";
const char kTokenSerialNumber[] = "Not Available";
const int kUserKeySize = 32;
const char kKeyPurposeEncrypt[] = "encrypt";
const char kKeyPurposeMac[] = "mac";
const char kAuthKeyMacInput[] = "arbitrary";

const struct MechanismInfo {
  CK_MECHANISM_TYPE type;
  CK_MECHANISM_INFO info;
} kDefaultMechanismInfo[] = {
  {CKM_RSA_PKCS_KEY_PAIR_GEN, {512, 2048, CKF_GENERATE_KEY_PAIR | CKF_HW}},
  {CKM_RSA_PKCS, {512, 2048, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN |
      CKF_VERIFY}},
  {CKM_MD5_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
  {CKM_SHA1_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
  {CKM_SHA256_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
  {CKM_SHA384_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
  {CKM_SHA512_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
  {CKM_MD5, {0, 0, CKF_DIGEST}},
  {CKM_SHA_1, {0, 0, CKF_DIGEST}},
  {CKM_SHA256, {0, 0, CKF_DIGEST}},
  {CKM_SHA384, {0, 0, CKF_DIGEST}},
  {CKM_SHA512, {0, 0, CKF_DIGEST}},
  {CKM_GENERIC_SECRET_KEY_GEN, {8, 1024, CKF_GENERATE}},
  {CKM_MD5_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
  {CKM_SHA_1_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
  {CKM_SHA256_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
  {CKM_SHA512_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
  {CKM_SHA384_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
  {CKM_DES_KEY_GEN, {0, 0, CKF_GENERATE}},
  {CKM_DES_ECB, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},
  {CKM_DES_CBC, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},
  {CKM_DES_CBC_PAD, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},
  {CKM_DES3_KEY_GEN, {0, 0, CKF_GENERATE}},
  {CKM_DES3_ECB, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},
  {CKM_DES3_CBC, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},
  {CKM_DES3_CBC_PAD, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},
  {CKM_AES_KEY_GEN, {16, 32, CKF_GENERATE}},
  {CKM_AES_ECB, {16, 32, CKF_ENCRYPT | CKF_DECRYPT}},
  {CKM_AES_CBC, {16, 32, CKF_ENCRYPT | CKF_DECRYPT}},
  {CKM_AES_CBC_PAD, {16, 32, CKF_ENCRYPT | CKF_DECRYPT}}
};

}  // namespace

SlotManagerImpl::SlotManagerImpl(std::shared_ptr<P11NetFactory> factory,
                                 bool auto_load_system_token)
    : factory_(factory),
      last_handle_(0),
      auto_load_system_token_(auto_load_system_token),
      is_initialized_(false) {
  CHECK(factory_);
}

SlotManagerImpl::~SlotManagerImpl() {}

bool SlotManagerImpl::Init() {
  // Populate mechanism info.
  for (size_t i = 0; i < arraysize(kDefaultMechanismInfo); ++i) {
    mechanism_info_[kDefaultMechanismInfo[i].type] =
        kDefaultMechanismInfo[i].info;
  }

  // Add default isolate.
  AddIsolate(IsolateCredentialManager::GetDefaultIsolateCredential());

  // By default we'll start with two slots.  This allows for one 'system' slot
  // which always has a token available, and one 'user' slot which will have no
  // token until a login event is received.
  AddSlots(1);

  InitStage2();
  return true;
}

bool SlotManagerImpl::InitStage2() {
  if (is_initialized_)
    return true;
  if (auto_load_system_token_) {
    boost::filesystem::path token_path(std::getenv("HOME"));
    token_path = token_path.append(".p11net");
    if (!boost::filesystem::create_directory(token_path)) {
      LOG(WARNING) << "System token not loaded because " <<
        token_path << " does not exist.";
    }
    // Setup the system token.
    int system_slot_id = 0;
    if (!LoadTokenInternal(
             IsolateCredentialManager::GetDefaultIsolateCredential(),
             token_path,
             SecureBlob(kSystemTokenAuthData),
             kSystemTokenLabel,
             &system_slot_id)) {
      LOG(ERROR) << "Failed to load the system token.";
      return false;
    }
  }
  is_initialized_ = true;
  return true;
}

int SlotManagerImpl::GetSlotCount() {
  InitStage2();
  return slot_list_.size();
}

bool SlotManagerImpl::IsTokenAccessible(const SecureBlob& isolate_credential,
                                        int slot_id) const {
  map<SecureBlob, Isolate>::const_iterator isolate_iter =
    isolate_map_.find(isolate_credential);
  if (isolate_iter == isolate_map_.end()) {
    return false;
  }
  const Isolate& isolate = isolate_iter->second;
  return isolate.slot_ids.find(slot_id) != isolate.slot_ids.end();
}

bool SlotManagerImpl::IsTokenPresent(const SecureBlob& isolate_credential,
                                     int slot_id) const {
  CHECK(IsTokenAccessible(isolate_credential, slot_id));
  return IsTokenPresent(slot_id);
}

void SlotManagerImpl::GetSlotInfo(const SecureBlob& isolate_credential,
                                  int slot_id, CK_SLOT_INFO* slot_info) const {
  CHECK(slot_info);
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));

  *slot_info = slot_list_[slot_id].slot_info;
}

void SlotManagerImpl::GetTokenInfo(const SecureBlob& isolate_credential,
                                   int slot_id,
                                   CK_TOKEN_INFO* token_info) const {
  CHECK(token_info);
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));
  CHECK(IsTokenPresent(slot_id));

  *token_info = slot_list_[slot_id].token_info;
}

const MechanismMap* SlotManagerImpl::GetMechanismInfo(
    const SecureBlob& isolate_credential, int slot_id) const {
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));
  CHECK(IsTokenPresent(slot_id));

  return &mechanism_info_;
}

int SlotManagerImpl::OpenSession(const SecureBlob& isolate_credential,
                                 int slot_id, bool is_read_only) {
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));
  CHECK(IsTokenPresent(slot_id));

  shared_ptr<Session> session(factory_->CreateSession(
      slot_id,
      slot_list_[slot_id].token_object_pool,
      slot_list_[slot_id].net_utility,
      shared_from_this(),
      is_read_only));
  CHECK(session.get());
  int session_id = CreateHandle();
  slot_list_[slot_id].sessions[session_id] = session;
  session_slot_map_[session_id] = slot_id;
  return session_id;
}

bool SlotManagerImpl::CloseSession(const SecureBlob& isolate_credential,
                                   int session_id) {
  Session* session = NULL;
  if (!GetSession(isolate_credential, session_id, &session))
    return false;
  CHECK(session);
  int slot_id = session_slot_map_[session_id];
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));
  session_slot_map_.erase(session_id);
  slot_list_[slot_id].sessions.erase(session_id);
  return true;
}

void SlotManagerImpl::CloseAllSessions(const SecureBlob& isolate_credential,
                                       int slot_id) {
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));

  for (map<int, shared_ptr<Session>>::iterator iter =
           slot_list_[slot_id].sessions.begin();
       iter != slot_list_[slot_id].sessions.end();
       ++iter) {
    session_slot_map_.erase(iter->first);
  }
  slot_list_[slot_id].sessions.clear();
}

bool SlotManagerImpl::GetSession(const SecureBlob& isolate_credential,
                                 int session_id, Session** session) const {
  CHECK(session);

  // Lookup which slot this session belongs to.
  map<int, int>::const_iterator session_slot_iter =
      session_slot_map_.find(session_id);
  if (session_slot_iter == session_slot_map_.end())
    return false;
  int slot_id = session_slot_iter->second;
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  if (!IsTokenAccessible(isolate_credential, slot_id)) {
    return false;
  }

  // Lookup the session instance.
  map<int, shared_ptr<Session>>::const_iterator session_iter =
      slot_list_[slot_id].sessions.find(session_id);
  if (session_iter == slot_list_[slot_id].sessions.end())
    return false;
  *session = session_iter->second.get();
  return true;
}

bool SlotManagerImpl::OpenIsolate(SecureBlob* isolate_credential,
                                  bool* new_isolate_created) {
  VLOG(1) << "SlotManagerImpl::OpenIsolate enter";

  CHECK(new_isolate_created);
  if (isolate_map_.find(*isolate_credential) != isolate_map_.end()) {
    VLOG(1) << "Incrementing open count for existing isolate.";
    Isolate& isolate = isolate_map_[*isolate_credential];
    ++isolate.open_count;
    *new_isolate_created = false;
  } else {
    VLOG(1) << "Creating new isolate.";
    std::string credential_string;
    credential_string.resize(kIsolateCredentialBytes);
    RAND_bytes(ConvertStringToByteBuffer(credential_string.data()),
               kIsolateCredentialBytes);
    SecureBlob new_isolate_credential(credential_string);
    ClearString(&credential_string);

    if (isolate_map_.find(new_isolate_credential) != isolate_map_.end()) {
      // A collision on 128 bits should be extremely unlikely if the random
      // number generator is working properly. If there is a problem with the
      // random number generator we want to get out.
      LOG(FATAL) << "Collision when trying to create new isolate credential.";
      return false;
    }

    AddIsolate(new_isolate_credential);
    isolate_credential->swap(new_isolate_credential);
    *new_isolate_created = true;
  }
  VLOG(1) << "SlotManagerImpl::OpenIsolate success";
  return true;
}

void SlotManagerImpl::CloseIsolate(const SecureBlob& isolate_credential) {
  VLOG(1) << "SlotManagerImpl::CloseIsolate enter";
  if (isolate_map_.find(isolate_credential) == isolate_map_.end()) {
    LOG(ERROR) << "Attempted Close isolate with invalid isolate credential";
    return;
  }
  Isolate& isolate = isolate_map_[isolate_credential];
  CHECK_GT(isolate.open_count, 0);
  --isolate.open_count;
  if (isolate.open_count == 0) {
    DestroyIsolate(isolate);
  }
  VLOG(1) << "SlotManagerImpl::CloseIsolate success";
}

bool SlotManagerImpl::LoadToken(const SecureBlob& isolate_credential,
                                const boost::filesystem::path& path,
                                const SecureBlob& auth_data,
                                const string& label,
                                int* slot_id) {
  if (!InitStage2())
    return false;
  return LoadTokenInternal(isolate_credential, path, auth_data, label, slot_id);
}

bool SlotManagerImpl::LoadTokenInternal(const SecureBlob& isolate_credential,
                                        const boost::filesystem::path& path,
                                        const SecureBlob& auth_data,
                                        const string& label,
                                        int* slot_id) {
  CHECK(slot_id);
  VLOG(1) << "SlotManagerImpl::LoadToken enter";
  if (isolate_map_.find(isolate_credential) == isolate_map_.end()) {
    LOG(ERROR) << "Invalid isolate credential for LoadToken.";
    return false;
  }
  Isolate& isolate = isolate_map_[isolate_credential];

  // If we're already managing this token, just send back the existing slot.
  if (path_slot_map_.find(path) != path_slot_map_.end()) {
    // TODO(rmcilroy): Consider allowing tokens to be loaded in multiple
    // isolates.
    LOG(WARNING) << "Load token event received for existing token.";
    *slot_id = path_slot_map_[path];
    return true;
  }
  // Setup the object pool.
  *slot_id = FindEmptySlot();
  std::unique_ptr<ObjectStore> object_store(factory_->CreateObjectStore(path));
  std::shared_ptr<ObjectPool> object_pool(
    factory_->CreateObjectPool(shared_from_this(), std::move(object_store)));
  CHECK(object_pool.get());

  // Load a software-only token.
  LOG(WARNING) << "Loading software-only token.";
  if (!LoadSoftwareToken(auth_data, object_pool.get())) {
    return false;
  }

  shared_ptr<NetUtility> net_utility(factory_->CreateNetUtility(object_pool));
  net_utility->Init();

  // Insert the new token into the empty slot.
  slot_list_[*slot_id].token_object_pool = object_pool;
  slot_list_[*slot_id].net_utility = net_utility;
  slot_list_[*slot_id].slot_info.flags |= CKF_TOKEN_PRESENT;
  path_slot_map_[path] = *slot_id;
  CopyStringToCharBuffer(label,
                         slot_list_[*slot_id].token_info.label,
                         arraysize(slot_list_[*slot_id].token_info.label));

  // Insert slot into the isolate.
  isolate.slot_ids.insert(*slot_id);
  LOG(INFO) << "Slot " << *slot_id << " ready for token at " << path;
  VLOG(1) << "SlotManagerImpl::LoadToken success";
  return true;
}

bool SlotManagerImpl::LoadSoftwareToken(const SecureBlob& auth_data,
                                        ObjectPool* object_pool) {
  SecureBlob auth_key_encrypt = Sha256(
      SecureBlob::Combine(auth_data, SecureBlob(kKeyPurposeEncrypt)));
  SecureBlob auth_key_mac = Sha256(
      SecureBlob::Combine(auth_data, SecureBlob(kKeyPurposeMac)));
  string encrypted_master_key;
  string saved_mac;
  if (!object_pool->GetInternalBlob(kEncryptedMasterKey,
                                    &encrypted_master_key) ||
      !object_pool->GetInternalBlob(kAuthDataHash, &saved_mac)) {
    return InitializeSoftwareToken(auth_data, object_pool);
  }
  if (HmacSha512(kAuthKeyMacInput, auth_key_mac) != saved_mac) {
    LOG(ERROR) << "Bad authorization data, reinitializing token.";
    if (!object_pool->DeleteAll())
      LOG(WARNING) << "Failed to delete all existing objects.";
    return InitializeSoftwareToken(auth_data, object_pool);
  }
  // Decrypt the master key with the auth data.
  string master_key_str;
  if (!RunCipher(false,  // Decrypt.
                 auth_key_encrypt,
                 std::string(),  // Use a random IV.
                 encrypted_master_key,
                 &master_key_str)) {
    LOG(ERROR) << "Failed to decrypt master key, reinitializing token.";
    if (!object_pool->DeleteAll())
      LOG(WARNING) << "Failed to delete all existing objects.";
    return InitializeSoftwareToken(auth_data, object_pool);
  }
  SecureBlob master_key(master_key_str);
  ClearString(&master_key_str);
  if (!object_pool->SetEncryptionKey(master_key)) {
    LOG(ERROR) << "SetEncryptionKey failed.";
    return false;
  }
  return true;
}

bool SlotManagerImpl::InitializeSoftwareToken(const SecureBlob& auth_data,
                                              ObjectPool* object_pool) {
  // Generate a new random master key and encrypt it with the auth data.
  SecureBlob master_key(kUserKeySize);
  if (1 != RAND_bytes(master_key.data(), kUserKeySize)) {
    LOG(ERROR) << "RAND_bytes failed: " << GetOpenSSLError();
    return false;
  }
  SecureBlob auth_key_encrypt = Sha256(
      SecureBlob::Combine(auth_data, SecureBlob(kKeyPurposeEncrypt)));
  string encrypted_master_key;
  if (!RunCipher(true,  // Encrypt.
                 auth_key_encrypt,
                 std::string(),  // Use a random IV.
                 master_key.to_string(),
                 &encrypted_master_key)) {
    LOG(ERROR) << "Failed to encrypt new master key.";
    return false;
  }
  SecureBlob auth_key_mac = Sha256(
      SecureBlob::Combine(auth_data, SecureBlob(kKeyPurposeMac)));
  if (!object_pool->SetInternalBlob(kEncryptedMasterKey,
                                    encrypted_master_key) ||
      !object_pool->SetInternalBlob(kAuthDataHash,
                                    HmacSha512(kAuthKeyMacInput,
                                               auth_key_mac))) {
    LOG(ERROR) << "Failed to write new master key blobs.";
    //return false;
  }
  if (!object_pool->SetEncryptionKey(master_key)) {
    LOG(ERROR) << "SetEncryptionKey failed.";
    return false;
  }
  return true;
}

void SlotManagerImpl::UnloadToken(const SecureBlob& isolate_credential,
                                  const boost::filesystem::path& path) {
  VLOG(1) << "SlotManagerImpl::UnloadToken";
  if (isolate_map_.find(isolate_credential) == isolate_map_.end()) {
    LOG(WARNING) << "Invalid isolate credential for UnloadToken.";
    return;
  }
  Isolate& isolate = isolate_map_[isolate_credential];

  // If we're not managing this token, ignore the event.
  if (path_slot_map_.find(path) == path_slot_map_.end()) {
    LOG(WARNING) << "Unload Token event received for unknown path: "
                 << path;
    return;
  }
  int slot_id = path_slot_map_[path];
  if (!IsTokenAccessible(isolate_credential, slot_id))
    LOG(WARNING) << "Attempted to unload token with invalid isolate credential";

  CloseAllSessions(isolate_credential, slot_id);
  slot_list_[slot_id].token_object_pool.reset();
  slot_list_[slot_id].net_utility.reset();
  slot_list_[slot_id].slot_info.flags &= ~CKF_TOKEN_PRESENT;
  path_slot_map_.erase(path);
  // Remove slot from the isolate.
  isolate.slot_ids.erase(slot_id);
  LOG(INFO) << "Token at " << path << " has been removed from slot "
            << slot_id;
  VLOG(1) << "SlotManagerImpl::Unload token success";
}

void SlotManagerImpl::ChangeTokenAuthData(const boost::filesystem::path& path,
                                          const SecureBlob& old_auth_data,
                                          const SecureBlob& new_auth_data) {
  if (!InitStage2()) {
    LOG(ERROR) << "Initialization failed; ignoring change auth event.";
    return;
  }
  // This event can be handled whether or not we are already managing the token
  // but if we're not, we won't start until a Load Token event comes in.
  std::shared_ptr<ObjectPool> object_pool;
  int slot_id = 0;
  if (path_slot_map_.find(path) == path_slot_map_.end()) {
    auto object_store = std::unique_ptr<ObjectStore>(factory_->CreateObjectStore(path));
    object_pool.reset(factory_->CreateObjectPool(shared_from_this(),
                                                 std::move(object_store)));
    slot_id = FindEmptySlot();
  } else {
    slot_id = path_slot_map_[path];
    object_pool = slot_list_[slot_id].token_object_pool;
  }
  CHECK(object_pool);

  // We're working with a software-only token.
  string encrypted_master_key;
  string saved_mac;
  if (!object_pool->GetInternalBlob(kEncryptedMasterKey,
                                    &encrypted_master_key) ||
      !object_pool->GetInternalBlob(kAuthDataHash, &saved_mac)) {
    LOG(INFO) << "Token not initialized; ignoring change auth data event.";
    return;
  }
  // Check if old_auth_data is valid.
  SecureBlob old_auth_key_mac = Sha256(
      SecureBlob::Combine(old_auth_data, SecureBlob(kKeyPurposeMac)));
  if (HmacSha512(kAuthKeyMacInput, old_auth_key_mac) != saved_mac) {
    LOG(ERROR) << "Old authorization data is not correct.";
    return;
  }
  // Decrypt the master key with the old_auth_data.
  SecureBlob old_auth_key_encrypt = Sha256(
      SecureBlob::Combine(old_auth_data, SecureBlob(kKeyPurposeEncrypt)));
  string master_key;
  if (!RunCipher(false,  // Decrypt.
                 old_auth_key_encrypt,
                 std::string(),  // Use a random IV.
                 encrypted_master_key,
                 &master_key)) {
    LOG(ERROR) << "Failed to decrypt master key with old auth data.";
    return;
  }
  // Encrypt the master key with the new_auth_data.
  SecureBlob new_auth_key_encrypt = Sha256(
      SecureBlob::Combine(new_auth_data, SecureBlob(kKeyPurposeEncrypt)));
  if (!RunCipher(true,  // Encrypt.
                 new_auth_key_encrypt,
                 std::string(),  // Use a random IV.
                 master_key,
                 &encrypted_master_key)) {
    LOG(ERROR) << "Failed to encrypt master key with new auth data.";
    return;
  }
  ClearString(&master_key);
  // Write out the new blobs.
  SecureBlob new_auth_key_mac = Sha256(
      SecureBlob::Combine(new_auth_data, SecureBlob(kKeyPurposeMac)));
  if (!object_pool->SetInternalBlob(kEncryptedMasterKey,
                                    encrypted_master_key) ||
      !object_pool->SetInternalBlob(kAuthDataHash,
                                    HmacSha512(kAuthKeyMacInput,
                                               new_auth_key_mac))) {
    LOG(ERROR) << "Failed to write new master key blobs.";
    return;
  }
}

bool SlotManagerImpl::GetTokenPath(const SecureBlob& isolate_credential,
                                   int slot_id,
                                   boost::filesystem::path* path) {
  if (!IsTokenAccessible(isolate_credential, slot_id))
    return false;
  if (!IsTokenPresent(slot_id))
    return false;
  return PathFromSlotId(slot_id, path);
}

bool SlotManagerImpl::IsTokenPresent(int slot_id) const {
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());

  return ((slot_list_[slot_id].slot_info.flags & CKF_TOKEN_PRESENT) ==
      CKF_TOKEN_PRESENT);
}

int SlotManagerImpl::CreateHandle() {
  boost::lock_guard<boost::mutex> lock(handle_generator_lock_);
  // If we use this many handles, we have a problem.
  CHECK(last_handle_ < std::numeric_limits<int>::max());
  return ++last_handle_;
}

void SlotManagerImpl::GetDefaultInfo(CK_SLOT_INFO* slot_info,
                                     CK_TOKEN_INFO* token_info) {
  memset(slot_info, 0, sizeof(CK_SLOT_INFO));
  CopyStringToCharBuffer(kSlotDescription,
                         slot_info->slotDescription,
                         arraysize(slot_info->slotDescription));
  CopyStringToCharBuffer(kManufacturerID,
                         slot_info->manufacturerID,
                         arraysize(slot_info->manufacturerID));
  slot_info->flags = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE;
  slot_info->hardwareVersion = kDefaultVersion;
  slot_info->firmwareVersion = kDefaultVersion;

  memset(token_info, 0, sizeof(CK_TOKEN_INFO));
  CopyStringToCharBuffer(kTokenLabel,
                         token_info->label,
                         arraysize(token_info->label));
  CopyStringToCharBuffer(kManufacturerID,
                         token_info->manufacturerID,
                         arraysize(token_info->manufacturerID));
  CopyStringToCharBuffer(kTokenModel,
                         token_info->model,
                         arraysize(token_info->model));
  CopyStringToCharBuffer(kTokenSerialNumber,
                         token_info->serialNumber,
                         arraysize(token_info->serialNumber));
  token_info->flags = CKF_RNG |
                      CKF_USER_PIN_INITIALIZED |
                      CKF_PROTECTED_AUTHENTICATION_PATH |
                      CKF_TOKEN_INITIALIZED;
  token_info->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
  token_info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
  token_info->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
  token_info->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
  token_info->ulMaxPinLen = kMaxPinLen;
  token_info->ulMinPinLen = kMinPinLen;
  token_info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  token_info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  token_info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  token_info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  token_info->hardwareVersion = kDefaultVersion;
  token_info->firmwareVersion = kDefaultVersion;
}

int SlotManagerImpl::FindEmptySlot() {
  size_t i = 0;
  for (; i < slot_list_.size(); ++i) {
    if (!IsTokenPresent(i))
      return i;
  }
  // Add a new slot.
  AddSlots(1);
  return i;
}

void SlotManagerImpl::AddSlots(int num_slots) {
  for (int i = 0; i < num_slots; ++i) {
    Slot slot;
    GetDefaultInfo(&slot.slot_info, &slot.token_info);
    LOG(INFO) << "Adding slot: " << slot_list_.size();
    slot_list_.push_back(slot);
  }
}

void SlotManagerImpl::AddIsolate(const SecureBlob& isolate_credential) {
  Isolate isolate;
  isolate.credential = isolate_credential;
  isolate.open_count = 1;
  isolate_map_[isolate_credential] = isolate;
}

void SlotManagerImpl::DestroyIsolate(const Isolate& isolate) {
  CHECK_EQ(isolate.open_count, 0);

  // Unload any existing tokens in this isolate.
  while (!isolate.slot_ids.empty()) {
    int slot_id = *isolate.slot_ids.begin();
    boost::filesystem::path path;
    CHECK(PathFromSlotId(slot_id, &path));
    UnloadToken(isolate.credential, path);
  }

  isolate_map_.erase(isolate.credential);
}

bool SlotManagerImpl::PathFromSlotId(int slot_id, boost::filesystem::path* path) const {
  CHECK(path);
  map<boost::filesystem::path, int>::const_iterator path_iter;
  for (path_iter = path_slot_map_.begin(); path_iter != path_slot_map_.end();
       ++path_iter) {
    if (path_iter->second == slot_id) {
      *path = path_iter->first;
      return true;
    }
  }
  return false;
}

}  // namespace p11net
