#include <iostream>
#include <stdexcept>
#include <string>

#include "crypto++/base64.h"
#include "crypto++/dsa.h"
#include "crypto++/osrng.h"
#include "crypto++/rsa.h"
#include <crypto++/cryptlib.h>
#include <crypto++/elgamal.h>
#include <crypto++/files.h>
#include <crypto++/hkdf.h>
#include <crypto++/nbtheory.h>
#include <crypto++/queue.h>
#include <crypto++/sha.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/ot_driver.hpp"

/*
 * Constructor
 */
OTDriver::OTDriver(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->AES_key = keys.first;
  this->HMAC_key = keys.second;
  this->cli_driver = std::make_shared<CLIDriver>();
}

/*
 * Send either m0 or m1 using OT. This function should:
 * 1) Sample a public DH value and send it to the receiver
 * 2) Receive the receiver's public value
 * 3) Encrypt m0 and m1 using different keys
 * 4) Send the encrypted values
 * You may find `byteblock_to_integer` and `integer_to_byteblock` useful
 * Disconnect and throw errors only for invalid MACs
 */
void OTDriver::OT_send(std::string m0, std::string m1) {
  auto dh_and_a_and_ga = crypto_driver->DH_initialize();
  auto dh = std::get<0>(dh_and_a_and_ga);
  auto a = byteblock_to_integer(std::get<1>(dh_and_a_and_ga));
  auto A = byteblock_to_integer(std::get<2>(dh_and_a_and_ga));
  SenderToReceiver_OTPublicValue_Message public_value;
  public_value.public_value = integer_to_byteblock(A);
  network_driver->send(
    crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &public_value)
  );
 
  auto receiver_data_and_ok = crypto_driver->decrypt_and_verify(AES_key, HMAC_key, network_driver->read());
  if (!receiver_data_and_ok.second) {
    network_driver->disconnect();
    throw std::runtime_error("Invalid MAC");
  }
  ReceiverToSender_OTPublicValue_Message receiver_public_value;
  receiver_public_value.deserialize(receiver_data_and_ok.first);

  auto B = byteblock_to_integer(receiver_public_value.public_value);
  auto inv_A = CryptoPP::EuclideanMultiplicativeInverse(A, DL_P);
  auto B_over_A = a_times_b_mod_c(B, inv_A, DL_P);
std::cout << "before key generation" << std::endl;
  auto k0 = crypto_driver->AES_generate_key(
    crypto_driver->DH_generate_shared_key(dh, integer_to_byteblock(a), integer_to_byteblock(B))
  );
  auto k1 = crypto_driver->AES_generate_key(
    crypto_driver->DH_generate_shared_key(dh, integer_to_byteblock(a), integer_to_byteblock(B_over_A))
  );
// std::cout << "after key generation" << std::endl;
// std::cout << B_to_the_a << std::endl;
// std::cout << B_over_A_to_the_a << std::endl;
  auto c0_and_iv0 = crypto_driver->AES_encrypt(k0, m0);
  auto c1_and_iv1 = crypto_driver->AES_encrypt(k1, m1);

  SenderToReceiver_OTEncryptedValues_Message encrypted_values;
  encrypted_values.e0 = c0_and_iv0.first;
  encrypted_values.e1 = c1_and_iv1.first;
  encrypted_values.iv0 = c0_and_iv0.second;
  encrypted_values.iv1 = c1_and_iv1.second;
  network_driver->send(
    crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &encrypted_values)
  );

std::cout << "OT_send done" << std::endl;
}

/*
 * Receive m_c using OT. This function should:
 * 1) Read the sender's public value
 * 2) Respond with our public value that depends on our choice bit
 * 3) Generate the appropriate key and decrypt the appropriate ciphertext
 * You may find `byteblock_to_integer` and `integer_to_byteblock` useful
 * Disconnect and throw errors only for invalid MACs
 */
std::string OTDriver::OT_recv(int choice_bit) {
  auto sender_data_and_ok = crypto_driver->decrypt_and_verify(
    AES_key, HMAC_key, network_driver->read()
  );
  if (!sender_data_and_ok.second) {
    network_driver->disconnect();
    throw std::runtime_error("Invalid MAC");
  }
  SenderToReceiver_OTPublicValue_Message sender_public_value;
  sender_public_value.deserialize(sender_data_and_ok.first);
  auto A = byteblock_to_integer(sender_public_value.public_value);

  auto dh_and_b_and_gb = crypto_driver->DH_initialize();
  auto dh = std::get<0>(dh_and_b_and_gb);
  auto b = byteblock_to_integer(std::get<1>(dh_and_b_and_gb));
  auto gb = byteblock_to_integer(std::get<2>(dh_and_b_and_gb));
std::cout << gb << std::endl;
std::cout << a_exp_b_mod_c(DL_G, b, DL_P) << std::endl;
  CryptoPP::Integer pub = (choice_bit == 0) ? gb : a_times_b_mod_c(gb, A, DL_P);

  ReceiverToSender_OTPublicValue_Message public_value;
  public_value.public_value = integer_to_byteblock(pub);
  network_driver->send(
    crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &public_value)
  );

  auto ciphertexts_data_and_ok = crypto_driver->decrypt_and_verify(
    AES_key, HMAC_key, network_driver->read()
  );
  if (!ciphertexts_data_and_ok.second) {
    throw std::runtime_error("Invalid MAC");
  }
  SenderToReceiver_OTEncryptedValues_Message ciphertexts;
  ciphertexts.deserialize(ciphertexts_data_and_ok.first);


std::cout << "before key generation in recv" << std::endl;
std::cout << a_exp_b_mod_c(A, b, DL_P).BitCount() << std::endl;
  auto k = crypto_driver->AES_generate_key(
    crypto_driver->DH_generate_shared_key(dh, integer_to_byteblock(b), integer_to_byteblock(A))
  );
std::cout << "after key generation in recv" << std::endl;

  if (choice_bit) {
std::cout << "decrypting e1" << std::endl;
    return crypto_driver->AES_decrypt(k, ciphertexts.iv1, ciphertexts.e1);
  } else {
std::cout << "decrypting e0" << std::endl;
    return crypto_driver->AES_decrypt(k, ciphertexts.iv0, ciphertexts.e0);
  }
}