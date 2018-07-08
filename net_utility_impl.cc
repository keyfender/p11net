// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net_utility_impl.h"

#include <base/logging.h>

#include "cppcodec/base64_default_url.hpp"

#include "p11net_factory.h"
#include "object.h"
#include "object_pool.h"
#include "p11net.h"
#include "nlohmann/json.hpp"

using JSON = nlohmann::json;

const std::string kApiPath = "/api/v0/";
namespace p11net {

namespace Env {
  const char* kUrl = "P11NET_URL";
  const char* kUser = "P11NET_USER";
  const char* kPassword = "P11NET_PASSWORD";
}

namespace Purpose {
  const std::string kEncrypt = "encrypt";
  const std::string kSign = "sign";
}

NetUtilityImpl::NetUtilityImpl(std::shared_ptr<ObjectPool> token_object_pool,
                               std::shared_ptr<P11NetFactory> factory)
    : token_object_pool_(token_object_pool),
      factory_(factory)
  {}

NetUtilityImpl::~NetUtilityImpl() {}

bool NetUtilityImpl::Init() {
  VLOG(1) << __PRETTY_FUNCTION__;
  const std::string url = std::getenv(Env::kUrl);
  const std::string user = std::getenv(Env::kUser);
  const std::string password = std::getenv(Env::kPassword);
  web::http::client::http_client_config config;
  web::http::client::credentials creds(user, password);
  config.set_credentials(creds);
  client_.emplace(url, config);
  is_initialized_ = true;
  return true;
}

bool NetUtilityImpl::LoadKeys(const std::string& key_id) {
  VLOG(1) << __PRETTY_FUNCTION__;
  std::vector<std::string> locations;
  if (key_id.empty()) {
    VLOG(1) << "Fetching key locations";
    auto response = client_->request(
      web::http::methods::GET, kApiPath + "keys").get();
    VLOG(1) << "Received response status code: " << response.status_code();
    auto const json = JSON::parse(response.extract_utf8string().get());
    VLOG(1) << "Response:\n" << json.dump(2);
    try {
      auto const arr = json.at("data");
      for (auto i = arr.begin(); i != arr.end(); ++i) {
        locations.push_back(i->at("location"));
      }
    }
    catch (JSON::exception& e) {
      VLOG(1) << "Invalid JSON structure: " << e.what();
      return false;
    }
    //nethsm_keys_loaded_ = true;
  } else {
    locations.push_back(kApiPath + "keys/" + key_id);
  }
  for (auto i = locations.begin(); i != locations.end(); ++i) {
    auto const loc = *i;
    VLOG(1) << "Fetching key " << loc;
    auto response = client_->request(web::http::methods::GET, loc).get();
    VLOG(1) << "Received response status code: " << response.status_code();
    auto const json = JSON::parse(response.extract_utf8string().get());
    VLOG(1) << "Response:\n" << json.dump(2);

    std::string id, modulus, public_exponent, purpose;
    bool forEncrypting, forSigning;
    try {
      id = json.at("data").at("id");
      modulus = base64::decode<std::string>(
        json.at("data").at("publicKey").at("modulus")
        .get<std::string>());
      public_exponent = base64::decode<std::string>(
        json.at("data").at("publicKey").at("publicExponent")
        .get<std::string>());
      purpose = json.at("data").at("purpose");
      forEncrypting = boost::contains(purpose, Purpose::kEncrypt);
      forSigning = boost::contains(purpose, Purpose::kSign);
    }
    catch (JSON::exception& e) {
      VLOG(1) << "Invalid JSON structure: " << e.what();
      return false;
    }

    std::unique_ptr<Object> public_object(factory_->CreateObject());
    CHECK(public_object.get());
    public_object->SetAttributeString(CKA_ID, id);
    public_object->SetAttributeString(CKA_LABEL, id);
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
    private_object->SetAttributeString(CKA_LABEL, id);
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
  VLOG(1) << __PRETTY_FUNCTION__;
  std::string encrypted_data_b64 = base64::encode(encrypted_data);
  JSON body;
  body["encrypted"] = encrypted_data_b64;
  VLOG(1) << "Request:\n" << body.dump(2);
  auto response = client_->request(web::http::methods::POST,
    key_loc + "/actions/pkcs1/decrypt", body.dump(), "application/json").get();
  VLOG(1) << "Received response status code: " << response.status_code();
  auto const json = JSON::parse(response.extract_utf8string().get());
  VLOG(1) << "Response:\n" << json.dump(2);
  std::string result;
  try {
    result = base64::decode<std::string>(
      json.at("data").at("decrypted").get<std::string>());
  }
  catch (JSON::exception& e) {
    VLOG(1) << "Invalid JSON structure: " << e.what();
  }
  return result;
}

boost::optional<std::string> NetUtilityImpl::Sign(
    const std::string& key_loc,
    const std::string& data) {
  VLOG(1) << __PRETTY_FUNCTION__;
  std::string data_b64 = base64::encode(data);
  JSON body;
  body["message"] = data_b64;
  VLOG(1) << "Request:\n" << body.dump(2);
  auto response = client_->request(web::http::methods::POST,
    key_loc + "/actions/pkcs1/sign", body.dump(), "application/json").get();
  VLOG(1) << "Received response status code: " << response.status_code();
  auto const json = JSON::parse(response.extract_utf8string().get());
  VLOG(1) << "Response:\n" << json.dump(2);
  std::string result;
  try {
    result = base64::decode<std::string>(
      json.at("data").at("signedMessage").get<std::string>());
  }
  catch (JSON::exception& e) {
    VLOG(1) << "Invalid JSON structure: " << e.what();
  }
  return result;
}

}  // namespace p11net
