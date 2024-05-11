#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

/**
 * Get message type.
 */
MessageType::T get_message_type(std::vector<unsigned char> &data) {
  return (MessageType::T)data[0];
}

// ================================================
// SERIALIZERS
// ================================================

/**
 * Puts the bool b into the end of data.
 */
int put_bool(bool b, std::vector<unsigned char> &data) {
  data.push_back((char)b);
  return 1;
}

/**
 * Puts the string s into the end of data.
 */
int put_string(std::string s, std::vector<unsigned char> &data) {
  // Put length
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t str_size = s.size();
  std::memcpy(&data[idx], &str_size, sizeof(size_t));

  // Put string
  data.insert(data.end(), s.begin(), s.end());
  return data.size() - idx;
}

/**
 * Puts the integer i into the end of data.
 */
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data) {
  return put_string(CryptoPP::IntToString(i), data);
}

/**
 * Puts the nest bool from data at index idx into b.
 */
int get_bool(bool *b, std::vector<unsigned char> &data, int idx) {
  *b = (bool)data[idx];
  return 1;
}

/**
 * Puts the nest string from data at index idx into s.
 */
int get_string(std::string *s, std::vector<unsigned char> &data, int idx) {
  // Get length
  size_t str_size;
  std::memcpy(&str_size, &data[idx], sizeof(size_t));

  // Get string
  std::vector<unsigned char> svec(&data[idx + sizeof(size_t)],
                                  &data[idx + sizeof(size_t) + str_size]);
  *s = chvec2str(svec);
  return sizeof(size_t) + str_size;
}

/**
 * Puts the next integer from data at index idx into i.
 */
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx) {
  std::string i_str;
  int n = get_string(&i_str, data, idx);
  *i = CryptoPP::Integer(i_str.c_str());
  return n;
}

// ================================================
// WRAPPERS
// ================================================

/**
 * serialize HMACTagged_Wrapper.
 */
void HMACTagged_Wrapper::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::HMACTagged_Wrapper);

  // Add fields.
  put_string(chvec2str(this->payload), data);

  std::string iv = byteblock_to_string(this->iv);
  put_string(iv, data);

  put_string(this->mac, data);
}

/**
 * deserialize HMACTagged_Wrapper.
 */
int HMACTagged_Wrapper::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::HMACTagged_Wrapper);

  // Get fields.
  std::string payload_string;
  int n = 1;
  n += get_string(&payload_string, data, n);
  this->payload = str2chvec(payload_string);

  std::string iv;
  n += get_string(&iv, data, n);
  this->iv = string_to_byteblock(iv);

  n += get_string(&this->mac, data, n);
  return n;
}

// ================================================
// KEY EXCHANGE
// ================================================

/**
 * serialize DHPublicValue_Message.
 */
void DHPublicValue_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::DHPublicValue_Message);

  // Add fields.
  std::string public_string = byteblock_to_string(this->public_value);
  put_string(public_string, data);
}

/**
 * deserialize DHPublicValue_Message.
 */
int DHPublicValue_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::DHPublicValue_Message);

  // Get fields.
  std::string public_string;
  int n = 1;
  n += get_string(&public_string, data, n);
  this->public_value = string_to_byteblock(public_string);
  return n;
}

// ================================================
// ZKP
// ================================================

void SchnorrZKP::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::SchnorrZKP_Struct);
  put_bool(this->claim, data);
  put_integer(this->first_message, data);
  put_integer(this->response, data);
  put_string(byteblock_to_string(this->hash_component), data);
}

int SchnorrZKP::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::SchnorrZKP_Struct);
  int n = 1;
  n += get_bool(&this->claim, data, n);
  n += get_integer(&this->first_message, data, n);
  n += get_integer(&this->response, data, n);

  std::string hash_comp;
  n += get_string(&hash_comp, data, n);
  this->hash_component = string_to_byteblock(hash_comp);
  return n;
}

void GateZKP::serialize(std::vector<unsigned char> &data) {
  return;
  // data.push_back((char)MessageType::SchnorrZKP_Struct);

  // std::vector<unsigned char>* slice = &data;
  // data.
  // for (int i = 0; i < 3; i++) {

  // }
  // put_bool(this->claim, data);
  // put_integer(this->first_message, data);
  // put_integer(this->response, data);
  // put_string(byteblock_to_string(this->hash_component), data);
}

int GateZKP::deserialize(std::vector<unsigned char> &data) {
  return 0;
}

void DisjunctiveZKP::serialize(std::vector<unsigned char> &data) {
  return;
}

int DisjunctiveZKP::deserialize(std::vector<unsigned char> &data) {
  return 0;
}

void CommitmentReveal::serialize(std::vector<unsigned char> &data) {
  return;
}

int CommitmentReveal::deserialize(std::vector<unsigned char> &data) {
  return 0;
}

void VerifierToProver_AlternateGenerator_Message::serialize(std::vector<unsigned char> &data) {
  return;
}

int VerifierToProver_AlternateGenerator_Message::deserialize(std::vector<unsigned char> &data) {
  return 0;
}

void ProverToVerifier_NIZK_Message::serialize(std::vector<unsigned char> &data) {
  return;
}

int ProverToVerifier_NIZK_Message::deserialize(std::vector<unsigned char> &data) {
  return 0;
}














