#include <algorithm>
#include <crypto++/misc.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/prover.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor. Note that the OT_driver is left uninitialized.
 */
ProverClient::ProverClient(Circuit circuit,
                             std::shared_ptr<NetworkDriver> network_driver,
                             std::shared_ptr<CryptoDriver> crypto_driver) {
  this->circuit = circuit;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  initLogger(logging::trivial::severity_level::trace);
}

/**
 * Handle key exchange with evaluator
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
ProverClient::HandleKeyExchange() {
  // Generate private/public DH keys
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^b
  DHPublicValue_Message garbler_public_value_s;
  garbler_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> garbler_public_value_data;
  garbler_public_value_s.serialize(garbler_public_value_data);
  network_driver->send(garbler_public_value_data);

  // Listen for g^a
  std::vector<unsigned char> evaluator_public_value_data =
      network_driver->read();
  DHPublicValue_Message evaluator_public_value_s;
  evaluator_public_value_s.deserialize(evaluator_public_value_data);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      evaluator_public_value_s.public_value);
  CryptoPP::SecByteBlock AES_key =
      this->crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      this->crypto_driver->HMAC_generate_key(DH_shared_key);
  auto keys = std::make_pair(AES_key, HMAC_key);
  return keys;
}

/**
 * 0) Receives alternate generator from verifier
 * 1) Actually evaluates the circuit using the secret witness. Wire values
 *    are stored in an array.
 * 2) Commits to every wire value, stores commitment pairs in parallel array.
 * 2.5) Opens commitments for public wires (input/output)
 * 3) Calculates ZKPs for every gate (done in crypto_driver). This also provides
 *    the challenge value (hashed for fiat-shamir)
 * 4) Sends a single message to the verifier, containing:
 *    - Commitments for all wire values
 *    - Opened commitments for public wires (input/output)
 *    - ZKPs for every gate
 */
void ProverClient::run(std::vector<bool> public_input, std::vector<bool> witness) {
  // Key exchange
  auto keys = this->HandleKeyExchange();
  auto AES_key = keys.first;
  auto HMAC_key = keys.second;

  // Receive alternate generator
  auto alt_gen_data_and_ok = crypto_driver->decrypt_and_verify(
    AES_key, HMAC_key, network_driver->read()
  );
  if (!alt_gen_data_and_ok.second) {
    network_driver->disconnect();
    throw std::runtime_error("Failed to decrypt and verify alternate generator");
  }

  // Deserialize alternate generator
  VerifierToProver_AlternateGenerator_Message alt_gen_msg;
  alt_gen_msg.deserialize(alt_gen_data_and_ok.first);
  CryptoPP::Integer alt_gen = alt_gen_msg.alternate_generator;

  // Evaluate circuit
  std::vector<bool> wire_values;
  wire_values.reserve(this->circuit.num_wire);

  for (int i = 0; i < this->circuit.public_input_length; i++) {
    wire_values.push_back(public_input[i]);
  }

  for (int i = this->circuit.public_input_length; i < circuit.public_input_length + circuit.witness_input_length; i++) {
    wire_values.push_back(witness[i]);
  }

  for (int i = 0; i < this->circuit.num_gate; i++) {
    bool lhs = wire_values[this->circuit.gates[i].lhs];
    bool rhs = wire_values[this->circuit.gates[i].rhs];
    bool out = (!lhs || !rhs); // evaluate NAND
    wire_values[this->circuit.gates[i].output] = out;
  }

  if (wire_values[this->circuit.num_wire - 1] != 1) {
    throw std::runtime_error("Output wire value is not 1");
  }

  // Commit to wire values
  std::vector<CommitmentReveal> commitments;
  for (int i = 0; i < this->circuit.num_wire; i++) {
    CommitmentReveal com = crypto_driver->pedersen_commit(wire_values[i], alt_gen);
    commitments.push_back(com);
  }

  // Generate ZKPs for every gate
  std::vector<DisjunctiveZKP> zkps;
  for (int i = 0; i < this->circuit.num_gate; i++) {
    DisjunctiveZKP zkp = crypto_driver->disjunctZKP_gen(
      wire_values[this->circuit.gates[i].lhs],
      wire_values[this->circuit.gates[i].rhs],
      wire_values[this->circuit.gates[i].output],
      commitments[this->circuit.gates[i].lhs],
      commitments[this->circuit.gates[i].rhs],
      commitments[this->circuit.gates[i].output]
    );
    zkps.push_back(zkp);
  }

  // Send message to verifier
  ProverToVerifier_NIZK_Message prover_msg;
  prover_msg.commitments.reserve(this->circuit.num_wire);
  prover_msg.openings.reserve(this->circuit.public_input_length+1);
  prover_msg.zkps.reserve(this->circuit.num_gate);

  for (int i = 0; i < this->circuit.num_wire; i++) {
    prover_msg.commitments.push_back(commitments[i].commitment);
  }
  for (int i = 0; i < this->circuit.public_input_length+1; i++) {
    prover_msg.openings.push_back(commitments[i]);
  }
  for (int i = 0; i < this->circuit.num_gate; i++) {
    prover_msg.zkps.push_back(zkps[i]);
  }

  network_driver->send(
    crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &prover_msg)
  );

  return;
}