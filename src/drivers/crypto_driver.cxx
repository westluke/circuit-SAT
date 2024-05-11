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
#include <crypto++/nbtheory.h>
#include <crypto++/queue.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Encrypts the given message using AES and tags the ciphertext with an
 * HMAC. Outputs an HMACTagged_Wrapper as bytes.
 */
std::vector<unsigned char>
CryptoDriver::encrypt_and_tag(SecByteBlock AES_key, SecByteBlock HMAC_key,
                              Serializable *message) {
  // Serialize given message.
  std::vector<unsigned char> plaintext;
  message->serialize(plaintext);

  // Encrypt the payload, generate iv to hmac.
  std::pair<std::string, SecByteBlock> encrypted =
      this->AES_encrypt(AES_key, chvec2str(plaintext));
  std::string to_tag = std::string((const char *)encrypted.second.data(),
                                   encrypted.second.size()) +
                       encrypted.first;

  // Generate HMAC on the payload.
  HMACTagged_Wrapper msg;
  msg.payload = str2chvec(encrypted.first);
  msg.iv = encrypted.second;
  msg.mac = this->HMAC_generate(HMAC_key, to_tag);

  // Serialize the HMAC and payload.
  std::vector<unsigned char> payload_data;
  msg.serialize(payload_data);
  return payload_data;
}

/**
 * @brief Verifies that the tagged HMAC is valid on the ciphertext and decrypts
 * the given message using AES. Takes in an HMACTagged_Wrapper as bytes.
 */
std::pair<std::vector<unsigned char>, bool>
CryptoDriver::decrypt_and_verify(SecByteBlock AES_key, SecByteBlock HMAC_key,
                                 std::vector<unsigned char> ciphertext_data) {
  // Deserialize
  HMACTagged_Wrapper ciphertext;
  ciphertext.deserialize(ciphertext_data);

  // Verify HMAC
  std::string to_verify =
      std::string((const char *)ciphertext.iv.data(), ciphertext.iv.size()) +
      chvec2str(ciphertext.payload);
  bool valid = this->HMAC_verify(HMAC_key, to_verify, ciphertext.mac);

  // Decrypt
  std::string plaintext =
      this->AES_decrypt(AES_key, ciphertext.iv, chvec2str(ciphertext.payload));
  std::vector<unsigned char> plaintext_data = str2chvec(plaintext);
  return std::make_pair(plaintext_data, valid);
}

/**
 * @brief Generate DH keypair.
 */
std::tuple<DH, SecByteBlock, SecByteBlock> CryptoDriver::DH_initialize() {
  DH DH_obj(DL_P, DL_Q, DL_G);
  AutoSeededRandomPool prng;
  SecByteBlock DH_private_key(DH_obj.PrivateKeyLength());
  SecByteBlock DH_public_key(DH_obj.PublicKeyLength());
  DH_obj.GenerateKeyPair(prng, DH_private_key, DH_public_key);
  return std::make_tuple(DH_obj, DH_private_key, DH_public_key);
}

/**
 * @brief Generates a shared secret.
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  SecByteBlock DH_shared_key(DH_obj.AgreedValueLength());
  SecByteBlock private_key_real =
      SecByteBlock(NULL, DH_obj.PrivateKeyLength() - DH_private_value.size()) +
      DH_private_value;
  SecByteBlock other_key_real =
      SecByteBlock(NULL,
                   DH_obj.PublicKeyLength() - DH_other_public_value.size()) +
      DH_other_public_value;
  if (!DH_obj.Agree(DH_shared_key, private_key_real, other_key_real)) {
    throw std::runtime_error("Error: failed to reach shared secret.");
  }
  return DH_shared_key;
}

/**
 * @brief Generates AES key using HKDF with a salt.
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());
  // Derive AES key using HKDF
  SecByteBlock AES_shared_key(AES::DEFAULT_KEYLENGTH);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(AES_shared_key, AES_shared_key.size(), DH_shared_key,
                 DH_shared_key.size(), aes_salt, aes_salt.size(), NULL, 0);

  return AES_shared_key;
}

/**
 * @brief Encrypts the given plaintext.
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext) {
  try {
    // Create encryptor and set key
    CBC_Mode<AES>::Encryption AES_encryptor = CBC_Mode<AES>::Encryption();

    SecByteBlock iv(AES::BLOCKSIZE);
    AutoSeededRandomPool rng;
    AES_encryptor.GetNextIV(rng, iv.BytePtr());
    AES_encryptor.SetKeyWithIV(key, key.size(), iv);

    // Encrypt using a StreamTransformationFilter
    std::string ciphertext;
    StringSource ss1(plaintext, true,
                     new StreamTransformationFilter(
                         AES_encryptor, new StringSink(ciphertext)));

    return std::make_pair(ciphertext, iv);
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext.
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {
    CBC_Mode<AES>::Decryption AES_decryptor = CBC_Mode<AES>::Decryption();
    AES_decryptor.SetKeyWithIV(key, key.size(), iv);

    // Decrypt using a StreamTransformationFilter
    std::string recovered;
    StringSource ss1(ciphertext, true,
                     new StreamTransformationFilter(AES_decryptor,
                                                    new StringSink(recovered)));
    return recovered;
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt.
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  // Derive 256 byte ECB key from DH shared key using KDF
  HKDF<SHA256> hkdf;
  SecByteBlock HMAC_shared_key(SHA256::BLOCKSIZE);
  hkdf.DeriveKey(HMAC_shared_key, HMAC_shared_key.size(), DH_shared_key,
                 DH_shared_key.size(), hmac_salt, hmac_salt.size(), NULL, 0);
  return HMAC_shared_key;
}

/**
 * @brief Given a ciphertext, generates an HMAC
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    std::string mac;
    HMAC<SHA256> hmac(key, key.size());
    StringSource ss2(ciphertext, true,
                     new HashFilter(hmac, new StringSink(mac)));
    return mac;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks the MAC is valid.
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  try {
    HMAC<SHA256> hmac(key, key.size());
    StringSource(ciphertext + mac, true,
                 new HashVerificationFilter(hmac, NULL, flags));
    return true;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
}

/**
 * Hash inputs. SHA256(lhs || rhs)
 */
CryptoPP::SecByteBlock CryptoDriver::hash(CryptoPP::SecByteBlock to_hash) {
  CryptoPP::SHA256 hash;
  CryptoPP::SecByteBlock digest(hash.DigestSize());
  hash.Update(to_hash.BytePtr(), to_hash.size());
  hash.Final(digest.BytePtr());
  return digest;
}


CommitmentReveal CryptoDriver::pedersen_commit(bool secret, CryptoPP::Integer alt_gen) {
  assert(alt_gen < DL_P);
  assert(secret < DL_Q);
  AutoSeededRandomPool prng;
  CryptoPP::Integer r = CryptoPP::Integer(prng, 0, DL_Q-1);
  CryptoPP::Integer commitment = a_times_b_mod_c(
    a_exp_b_mod_c(DL_G, secret, DL_P),
    a_exp_b_mod_c(alt_gen, r, DL_P),
    DL_P
  );
  CommitmentReveal cr;
  cr.commitment = commitment;
  cr.randomness = r;
  cr.value = secret;
  return cr;
}

bool CryptoDriver::pedersen_verify(CommitmentReveal opening, CryptoPP::Integer alt_gen) {
  assert(opening.commitment < DL_P);
  assert(alt_gen < DL_P);
  assert(opening.value < DL_Q);
  assert(opening.randomness < DL_Q);

  return opening.commitment == a_times_b_mod_c(
    a_exp_b_mod_c(DL_G, opening.value, DL_P),
    a_exp_b_mod_c(alt_gen, opening.randomness, DL_P),
    DL_P
  );
}

bool CryptoDriver::schnorr_verify(
  CryptoPP::Integer exp,
  CryptoPP::Integer schnorr_first_msg,
  CryptoPP::Integer challenge,
  CryptoPP::Integer response
) {
  assert(schnorr_first_msg < DL_P);
  assert(challenge < DL_Q);
  assert(response < DL_Q);

  return a_exp_b_mod_c(DL_G, response, DL_P) == a_times_b_mod_c(
    schnorr_first_msg,
    a_exp_b_mod_c(exp, challenge, DL_P),
    DL_P
  );
}

// From a challenge and a exponentiation, figure out what the schnorr_first_msg and response should be
// to fool a verifier with that challenge into believing we know the log of the exponentiation
std::pair<CryptoPP::Integer, CryptoPP::Integer> CryptoDriver::reverse_schnorr(
  CryptoPP::Integer exp,
  CryptoPP::Integer commitment,
  CryptoPP::Integer challenge
) {
  assert(exp < DL_P);
  assert(commitment < DL_P);
  assert(challenge < DL_Q);

  AutoSeededRandomPool prng;
  CryptoPP::Integer response(prng, 0, DL_Q-1);
  CryptoPP::Integer g_inv = DL_G.InverseMod(DL_P);

  CryptoPP::Integer exp_to_the_challenge = a_exp_b_mod_c(exp, challenge, DL_P);
  CryptoPP::Integer g_to_the_response = a_exp_b_mod_c(DL_G, response, DL_P);
  CryptoPP::Integer schnorr_first_msg = a_times_b_mod_c(
    g_to_the_response,
    exp_to_the_challenge.InverseMod(DL_P),
    DL_P
  );

  assert(this->schnorr_verify(
    exp,
    schnorr_first_msg,
    challenge,
    response
  ));

  return std::pair(schnorr_first_msg, response);
}

CryptoPP::Integer CryptoDriver::schnorr_response(
  CryptoPP::Integer log,
  CryptoPP::Integer randomness,
  CryptoPP::Integer challenge
) {
  assert(randomness < DL_Q);
  assert(challenge < DL_Q);
  return (randomness + challenge * log) % DL_Q;
}

GateZKP CryptoDriver::GateZKP_gen(
  CryptoPP::Integer challenge,
  bool real_lhs, bool real_rhs, bool real_out,
  CommitmentReveal lhs_com, CommitmentReveal rhs_com, CommitmentReveal out_com
) {
  assert(lhs_com.commitment < DL_P);
  assert(rhs_com.commitment < DL_P);
  assert(out_com.commitment < DL_P);
  assert(challenge < DL_Q);

  AutoSeededRandomPool prng;

  GateZKP gate_zkp;
  CryptoPP::Integer g_inv = DL_G.InverseMod(DL_P);

  CryptoPP::Integer lhs_exp = lhs_com.commitment;
  CryptoPP::Integer rhs_exp = rhs_com.commitment;
  CryptoPP::Integer out_exp = out_com.commitment;
  CryptoPP::Integer lhs_r(prng, 0, DL_Q-1);
  CryptoPP::Integer rhs_r(prng, 0, DL_Q-1);
  CryptoPP::Integer out_r(prng, 0, DL_Q-1);

  // If the wires are true, we're not proving knowledge of an h-logarithm for the commitment,
  // but for the commitment divided by g.
  if (real_lhs) {
    lhs_exp = a_times_b_mod_c(lhs_exp, g_inv, DL_P);
  }
  if (real_rhs) {
    rhs_exp = a_times_b_mod_c(rhs_exp, g_inv, DL_P);
  }
  if (real_out) {
    out_exp = a_times_b_mod_c(out_exp, g_inv, DL_P);
  }

  SchnorrZKP lhs_zkp, rhs_zkp, out_zkp;

  lhs_zkp.claim = real_lhs;
  lhs_zkp.first_message = a_exp_b_mod_c(DL_G, lhs_r, DL_P);
  lhs_zkp.response = schnorr_response(lhs_exp, lhs_r, challenge);
  lhs_zkp.hash_component = integer_to_byteblock(CryptoPP::Integer(lhs_zkp.claim)) + integer_to_byteblock(lhs_zkp.first_message);

  rhs_zkp.claim = real_rhs;
  rhs_zkp.first_message = a_exp_b_mod_c(DL_G, rhs_r, DL_P);
  rhs_zkp.response = schnorr_response(rhs_exp, rhs_r, challenge);
  rhs_zkp.hash_component = integer_to_byteblock(CryptoPP::Integer(rhs_zkp.claim)) + integer_to_byteblock(rhs_zkp.first_message);

  out_zkp.claim = real_out;
  out_zkp.first_message = a_exp_b_mod_c(DL_G, out_r, DL_P);
  out_zkp.response = schnorr_response(out_exp, out_r, challenge);
  rhs_zkp.hash_component = integer_to_byteblock(CryptoPP::Integer(rhs_zkp.claim)) + integer_to_byteblock(rhs_zkp.first_message);

  gate_zkp.zkps.push_back(lhs_zkp);
  gate_zkp.zkps.push_back(rhs_zkp);
  gate_zkp.zkps.push_back(out_zkp);
  gate_zkp.challenge_component = challenge;
  gate_zkp.hash_component = lhs_zkp.hash_component + rhs_zkp.hash_component + out_zkp.hash_component;

  return gate_zkp;
}


// // Have to generate the REAL zkp later, since we don't know its challenge yet.
std::vector<GateZKP> CryptoDriver::fakeGateZKP_gen(
  bool real_lhs, bool real_rhs, bool real_out,
  CommitmentReveal lhs_com, CommitmentReveal rhs_com, CommitmentReveal out_com
) {
  std::vector<GateZKP> zkps;
  AutoSeededRandomPool prng;
  int counter = 0;
  CryptoPP::Integer g_inv = DL_G.InverseMod(DL_P);

  for (int lhs = 0; lhs < 2; lhs++) {
    for (int rhs = 0; rhs < 2; rhs++) {
      GateZKP gate_zkp;

      // Generate a set of Schnorr ZKPs for one possible set of inputs, using a random challenge
      bool out = nand(lhs, rhs);
      CryptoPP::Integer challenge = CryptoPP::Integer(prng, 0, DL_Q-1);
      CryptoPP::Integer lhs_exp = lhs_com.commitment;
      CryptoPP::Integer rhs_exp = rhs_com.commitment;
      CryptoPP::Integer out_exp = out_com.commitment;

      // If the wires are true, we're not proving knowledge of an h-logarithm for the commitment,
      // but for the commitment divided by g.
      if (lhs) {
        lhs_exp = a_times_b_mod_c(lhs_exp, g_inv, DL_P);
      }
      if (rhs) {
        rhs_exp = a_times_b_mod_c(rhs_exp, g_inv, DL_P);
      }
      if (out) {
        out_exp = a_times_b_mod_c(out_exp, g_inv, DL_P);
      }

      SchnorrZKP lhs_zkp, rhs_zkp, out_zkp;
      auto lhs_com_and_response = this->reverse_schnorr(lhs_exp, lhs_com.commitment, challenge);
      auto rhs_com_and_response = this->reverse_schnorr(rhs_exp, rhs_com.commitment, challenge);
      auto out_com_and_response = this->reverse_schnorr(out_exp, out_com.commitment, challenge);

      lhs_zkp.claim = lhs;
      lhs_zkp.first_message = lhs_com_and_response.first;
      lhs_zkp.response = lhs_com_and_response.second;
      lhs_zkp.hash_component = integer_to_byteblock(CryptoPP::Integer(lhs_zkp.claim)) + integer_to_byteblock(lhs_zkp.first_message);

      rhs_zkp.claim = rhs;
      rhs_zkp.first_message = rhs_com_and_response.first;
      rhs_zkp.response = rhs_com_and_response.second;
      rhs_zkp.hash_component = integer_to_byteblock(CryptoPP::Integer(rhs_zkp.claim)) + integer_to_byteblock(rhs_zkp.first_message);

      out_zkp.claim = out;
      out_zkp.first_message = out_com_and_response.first;
      out_zkp.response = out_com_and_response.second;
      out_zkp.hash_component = integer_to_byteblock(CryptoPP::Integer(out_zkp.claim)) + integer_to_byteblock(out_zkp.first_message);

      gate_zkp.zkps.push_back(lhs_zkp);
      gate_zkp.zkps.push_back(rhs_zkp);
      gate_zkp.zkps.push_back(out_zkp);
      gate_zkp.challenge_component = challenge;
      gate_zkp.hash_component = lhs_zkp.hash_component + rhs_zkp.hash_component + out_zkp.hash_component;

      zkps.push_back(gate_zkp);
    }
  }

  return zkps;
}

bool CryptoDriver::GateZKP_verify(
  GateZKP zkp, CryptoPP::Integer lhs_com, CryptoPP::Integer rhs_com, CryptoPP::Integer out_com
) {
  CryptoPP::SecByteBlock to_hash;
  std::vector<CryptoPP::Integer> coms;
  coms.push_back(lhs_com);
  coms.push_back(rhs_com);
  coms.push_back(out_com);

  for (int i = 0; i < 3; i++) {
    CryptoPP::Integer exp = coms[i];
    to_hash += zkp.zkps[i].hash_component;
    SchnorrZKP sch = zkp.zkps[i];

    if (sch.claim) {
      exp = a_times_b_mod_c(exp, DL_G.InverseMod(DL_P), DL_P);
    }

    if (!this->schnorr_verify(exp, sch.first_message, zkp.challenge_component, sch.response)) {
      return false;
    }
  }

  return true;
}

DisjunctiveZKP CryptoDriver::disjunctZKP_gen(
  bool lhs, bool rhs, bool out,
  CommitmentReveal lhs_com, CommitmentReveal rhs_com, CommitmentReveal out_com
) {
  assert(nand(lhs, rhs) == out);
  int real_idx = lhs * 2 + rhs;
  CryptoPP::SecByteBlock to_hash;
  CryptoPP::Integer fake_challenge_total;

  std::vector<GateZKP> gateZKPs = fakeGateZKP_gen(
    lhs, rhs, out, lhs_com, rhs_com, out_com
  );

  for (int i = 0; i < gateZKPs.size(); i++) {
    to_hash += gateZKPs[i].hash_component;
    if (i != real_idx) fake_challenge_total += gateZKPs[i].challenge_component;
  }

  CryptoPP::Integer challenge = byteblock_to_integer(this->hash(to_hash));

  gateZKPs[real_idx] = GateZKP_gen(
    challenge,
    lhs, rhs, out,
    lhs_com, rhs_com, out_com
  );

  DisjunctiveZKP disjunct_zkp;
  disjunct_zkp.zkps = gateZKPs;
  return disjunct_zkp;
}

bool CryptoDriver::disjunctZKP_verify(
  DisjunctiveZKP zkp, CryptoPP::Integer lhs_com, CryptoPP::Integer rhs_com, CryptoPP::Integer out_com
) {
  CryptoPP::SecByteBlock to_hash;
  CryptoPP::Integer challenge_sum = 0;
  for (int i = 0; i < 4; i++) {
    to_hash += zkp.zkps[i].hash_component;
    challenge_sum += zkp.zkps[i].challenge_component;
    if (!this->GateZKP_verify(zkp.zkps[i], lhs_com, rhs_com, out_com)) {
      return  false;
    }
  }

  if (challenge_sum != byteblock_to_integer(this->hash(to_hash))) {
    return false;
  }

  return true;
}