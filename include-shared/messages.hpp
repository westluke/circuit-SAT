#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dsa.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>

#include "../include-shared/circuit.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

namespace MessageType {
enum T {
  HMACTagged_Wrapper = 1,
  DHPublicValue_Message = 2,
  VerifierToProver_AlternateGenerator_Message = 3,
  ProverToVerifier_NIZK_Message = 4,
  SchnorrZKP_Struct = 5,
  GateZKP_Struct = 6,
  DisjunctiveZKP_Struct = 7,
  CommitmentReveal_Struct = 8
};
};
MessageType::T get_message_type(std::vector<unsigned char> &data);

// ================================================
// SERIALIZABLE
// ================================================

struct Serializable {
  virtual void serialize(std::vector<unsigned char> &data) = 0;
  virtual int deserialize(std::vector<unsigned char> &data) = 0;
};

// serializers.
int put_bool(bool b, std::vector<unsigned char> &data);
int put_string(std::string s, std::vector<unsigned char> &data);
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data);

// deserializers
int get_bool(bool *b, std::vector<unsigned char> &data, int idx);
int get_string(std::string *s, std::vector<unsigned char> &data, int idx);
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx);

// ================================================
// WRAPPERS
// ================================================

struct HMACTagged_Wrapper : public Serializable {
  std::vector<unsigned char> payload;
  CryptoPP::SecByteBlock iv;
  std::string mac;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// KEY EXCHANGE
// ================================================

struct DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// ZKP
// ================================================

struct SchnorrZKP : public Serializable {
  bool claim;
  CryptoPP::Integer first_message;
  CryptoPP::Integer response;
  CryptoPP::SecByteBlock hash_component;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct GateZKP : public Serializable {
  std::vector<SchnorrZKP> zkps;
  CryptoPP::Integer challenge_component;
  CryptoPP::SecByteBlock hash_component;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct DisjunctiveZKP : public Serializable {
  std::vector<GateZKP> zkps;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct CommitmentReveal : public Serializable {
  CryptoPP::Integer commitment;
  CryptoPP::Integer randomness;
  bool value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct VerifierToProver_AlternateGenerator_Message : public Serializable {
  CryptoPP::Integer alternate_generator;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ProverToVerifier_NIZK_Message : public Serializable {
  std::vector<CryptoPP::Integer> commitments;
  std::vector<CommitmentReveal> openings;
  std::vector<DisjunctiveZKP> zkps;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};