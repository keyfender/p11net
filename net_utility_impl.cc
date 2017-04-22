// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net_utility_impl.h"

#include "cppcodec/base64_default_url.hpp"

#include "chaps_factory.h"
#include "object.h"
#include "object_pool.h"
#include "chaps.h"

namespace chaps {

namespace Purpose {
  const std::string kEncrypt = "encrypt";
  const std::string kSign = "sign";
}

NetUtilityImpl::NetUtilityImpl(std::shared_ptr<ObjectPool> token_object_pool,
                               std::shared_ptr<ChapsFactory> factory)
    : token_object_pool_(token_object_pool),
      factory_(factory)
  {}

NetUtilityImpl::~NetUtilityImpl() {}

bool NetUtilityImpl::Init() {
  std::cout << __PRETTY_FUNCTION__ << std::endl;
  web::http::client::http_client_config config;
  web::http::client::credentials creds("admin", "secret");
  config.set_credentials(creds);
  client_.emplace(U("http://localhost:8080"), config);
  is_initialized_ = true;
  return true;
}

bool NetUtilityImpl::LoadKeys(const std::string& key_id) {
  std::cout << __PRETTY_FUNCTION__ << std::endl;
  std::vector<std::string> locations;
  if (key_id.empty()) {
    auto response = client_->request(web::http::methods::GET, "/api/v0/keys").get();
    printf("Received response status code:%u\n", response.status_code());
    auto json = response.extract_json().get();
    auto const arr = json["data"].as_array();
    for (auto i = arr.begin(); i != arr.end(); ++i) {
      auto const loc = i->at("location").as_string();
      locations.push_back(loc);
    }
    //nethsm_keys_loaded_ = true;
  } else {
    locations.push_back("/api/v0/keys/" + key_id);
  }
  for (auto i = locations.begin(); i != locations.end(); ++i) {
    auto const loc = *i;
    auto response = client_->request(web::http::methods::GET, loc).get();
    printf("Received response status code:%u\n", response.status_code());
    auto json = response.extract_json().get();
    auto const id = json["data"]["id"].as_string();
    auto const modulus = base64::decode<std::string>(
      json["data"]["publicKey"]["modulus"].as_string());
    auto const public_exponent = base64::decode<std::string>(
      json["data"]["publicKey"]["publicExponent"].as_string());
    auto const purpose = json["data"]["purpose"].as_string();
    const bool forEncrypting(boost::starts_with(purpose, Purpose::kEncrypt));
    const bool forSigning(boost::starts_with(purpose, Purpose::kSign));
    std::cout << loc << " -> " << id << std::endl;

    std::unique_ptr<Object> public_object(factory_->CreateObject());
    CHECK(public_object.get());
    public_object->SetAttributeString(CKA_ID, id);
    public_object->SetAttributeString(CKA_LABEL, loc);
    public_object->SetAttributeInt(CKA_CLASS, CKO_PUBLIC_KEY);
    public_object->SetAttributeInt(CKA_KEY_TYPE, CKK_RSA);
    public_object->SetAttributeBool(CKA_MODIFIABLE, false);
    public_object->SetAttributeBool(CKA_TOKEN, true);
    public_object->SetAttributeString(CKA_PUBLIC_EXPONENT, public_exponent);
    public_object->SetAttributeString(CKA_MODULUS, modulus);
    int modulus_bits = modulus.size()*8;
    public_object->SetAttributeInt(CKA_MODULUS_BITS, modulus_bits);
    if (forEncrypting) {
      public_object->SetAttributeBool(CKA_ENCRYPT, true);
    }
    if (forSigning) {
      public_object->SetAttributeBool(CKA_VERIFY, true);
    }

    std::unique_ptr<Object> private_object(factory_->CreateObject());
    CHECK(private_object.get());
    private_object->SetAttributeString(CKA_ID, id);
    private_object->SetAttributeString(CKA_LABEL, loc);
    private_object->SetAttributeInt(CKA_CLASS, CKO_PRIVATE_KEY);
    private_object->SetAttributeInt(CKA_KEY_TYPE, CKK_RSA);
    private_object->SetAttributeBool(CKA_MODIFIABLE, false);
    private_object->SetAttributeBool(CKA_TOKEN, true);
    private_object->SetAttributeBool(CKA_PRIVATE, true);
    private_object->SetAttributeBool(CKA_SENSITIVE, true);
    private_object->SetAttributeBool(CKA_EXTRACTABLE, false);
    private_object->SetAttributeBool(CKA_ALWAYS_SENSITIVE, true);
    private_object->SetAttributeBool(CKA_NEVER_EXTRACTABLE, true);
    private_object->SetAttributeString(CKA_PUBLIC_EXPONENT, public_exponent);
    private_object->SetAttributeString(kKeyLocationAttribute, loc);
    private_object->SetAttributeString(CKA_MODULUS, modulus);
    if (forEncrypting) {
      private_object->SetAttributeBool(CKA_DECRYPT, true);
    }
    if (forSigning) {
      private_object->SetAttributeBool(CKA_SIGN, true);
    }

    if (public_object->FinalizeNewObject() != CKR_OK)
      continue;
    if (private_object->FinalizeNewObject() != CKR_OK)
      continue;
    if (!token_object_pool_->Insert(public_object.get()))
      continue;
    if (!token_object_pool_->Insert(private_object.get())) {
      token_object_pool_->Delete(public_object.get());
      continue;
    }
    public_object.release();
    private_object.release();
  }
  return true;
}

boost::optional<std::string> NetUtilityImpl::Decrypt(
    const std::string& key_loc,
    const std::string& encrypted_data) {
  std::cout << __PRETTY_FUNCTION__ << std::endl;
  std::string encrypted_data_b64 = base64::encode(encrypted_data);
  auto body = web::json::value::parse("{\"encrypted\": \"" + encrypted_data_b64 + "\"}");

  auto response = client_->request(web::http::methods::POST,
                                 key_loc + "/actions/pkcs1/decrypt", body).get();
  printf("Received response status code:%u\n", response.status_code());
  auto json = response.extract_json().get();
  std::cout << json.serialize() << std::endl;
  std::string result = base64::decode<std::string>(json["data"]["decrypted"].as_string());
  return result;
}

boost::optional<std::string> NetUtilityImpl::Sign(
    const std::string& key_loc,
    const std::string& data) {
  std::cout << __PRETTY_FUNCTION__ << std::endl;
  std::string data_b64 = base64::encode(data);
  auto body = web::json::value::parse("{\"message\": \"" + data_b64 + "\"}");

  auto response = client_->request(web::http::methods::POST,
                                 key_loc + "/actions/pkcs1/sign", body).get();
  printf("Received response status code:%u\n", response.status_code());
  auto json = response.extract_json().get();
  std::cout << json.serialize() << std::endl;
  std::string result = base64::decode<std::string>(json["data"]["signedMessage"].as_string());
  return result;
}

}  // namespace chaps
