#pragma once

#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/dsa.h>
#include <crypto++/elgamal.h>
#include <crypto++/files.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/hkdf.h>
#include <crypto++/hmac.h>
#include <crypto++/integer.h>
#include <crypto++/modes.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rijndael.h>
#include <crypto++/sha.h>

#include "../../include-shared/messages.hpp"

using namespace CryptoPP;

class CryptoDriver {
public:
  std::vector<unsigned char> encrypt_and_tag(SecByteBlock AES_key,
                                             SecByteBlock HMAC_key,
                                             Serializable *message);
  std::pair<std::vector<unsigned char>, bool>
  decrypt_and_verify(SecByteBlock AES_key, SecByteBlock HMAC_key,
                     std::vector<unsigned char> ciphertext_data);

  std::tuple<DH, SecByteBlock, SecByteBlock> DH_initialize();
  SecByteBlock
  DH_generate_shared_key(const DH &DH_obj, const SecByteBlock &DH_private_value,
                         const SecByteBlock &DH_other_public_value);

  SecByteBlock AES_generate_key(const SecByteBlock &DH_shared_key);
  std::pair<std::string, SecByteBlock> AES_encrypt(SecByteBlock key,
                                                   std::string plaintext);
  std::string AES_decrypt(SecByteBlock key, SecByteBlock iv,
                          std::string ciphertext);

  SecByteBlock HMAC_generate_key(const SecByteBlock &DH_shared_key);
  std::string HMAC_generate(SecByteBlock key, std::string ciphertext);
  bool HMAC_verify(SecByteBlock key, std::string ciphertext, std::string hmac);

  CryptoPP::SecByteBlock hash(CryptoPP::SecByteBlock to_hash);

  CommitmentReveal pedersen_commit(bool secret, CryptoPP::Integer alt_gen);
  bool pedersen_verify(CommitmentReveal opening, CryptoPP::Integer alt_gen);

  bool schnorr_verify(
    CryptoPP::Integer exp,
    CryptoPP::Integer schnorr_first_msg,
    CryptoPP::Integer challenge,
    CryptoPP::Integer response
  );

  std::pair<CryptoPP::Integer, CryptoPP::Integer> reverse_schnorr(
    CryptoPP::Integer exp,
    CryptoPP::Integer commitment,
    CryptoPP::Integer challenge
  );

  CryptoPP::Integer schnorr_response(
    CryptoPP::Integer log,
    CryptoPP::Integer randomness,
    CryptoPP::Integer challenge
  );

  GateZKP GateZKP_gen(
    CryptoPP::Integer challenge,
    bool real_lhs, bool real_rhs, bool real_out,
    CommitmentReveal lhs_com, CommitmentReveal rhs_com, CommitmentReveal out_com);

  std::vector<GateZKP> fakeGateZKP_gen(
    bool real_lhs, bool real_rhs, bool real_out,
    CommitmentReveal lhs_com, CommitmentReveal rhs_com, CommitmentReveal out_com);

  bool GateZKP_verify(
    GateZKP zkp, CryptoPP::Integer lhs_com, CryptoPP::Integer rhs_com, CryptoPP::Integer out_com
  );

  DisjunctiveZKP disjunctZKP_gen(
    bool lhs, bool rhs, bool out,
    CommitmentReveal lhs_com, CommitmentReveal rhs_com, CommitmentReveal out_com
  );

  bool disjunctZKP_verify(
    DisjunctiveZKP zkp, CryptoPP::Integer lhs_com, CryptoPP::Integer rhs_com, CryptoPP::Integer out_com
  );
};
