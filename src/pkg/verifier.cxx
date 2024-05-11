#include "../../include/pkg/verifier.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

VerifierClient::VerifierClient(Circuit circuit,
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
VerifierClient::HandleKeyExchange() {
  // Generate private/public DH keys
  auto dh_values = this->crypto_driver->DH_initialize();

  // Listen for g^b
  std::vector<unsigned char> garbler_public_value_data = network_driver->read();
  DHPublicValue_Message garbler_public_value_s;
  garbler_public_value_s.deserialize(garbler_public_value_data);

  // Send g^a
  DHPublicValue_Message evaluator_public_value_s;
  evaluator_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> evaluator_public_value_data;
  evaluator_public_value_s.serialize(evaluator_public_value_data);
  network_driver->send(evaluator_public_value_data);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      garbler_public_value_s.public_value);
  CryptoPP::SecByteBlock AES_key =
      this->crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      this->crypto_driver->HMAC_generate_key(DH_shared_key);
  auto keys = std::make_pair(AES_key, HMAC_key);
  return keys;
}

/**
 * 1) Generates alternate generator h value and sends to prover
 * 2) Receives message from prover, containing:
 *    - Commitments for all wire values
 *    - Opened commitments for public wires (input/output)
 *    - ZKPs for every gate
 * 3) Verifies commitments for public wires
 * 4) Verifies ZKPs for every gate
 * 5) If all checks pass, returns "1", else "0"
 */
bool VerifierClient::run(std::vector<bool> public_input) {

  // // Key exchange
  auto keys = this->HandleKeyExchange();
  auto AES_key = keys.first;
  auto HMAC_key = keys.second;

  // Generate alternate generator h value
  AutoSeededRandomPool prng;
  CryptoPP::Integer h_log(prng, 1, DL_Q);
  CryptoPP::Integer h = a_exp_b_mod_c(DL_G, h_log, DL_P);

  // Send h to prover
  VerifierToProver_AlternateGenerator_Message h_msg;
  h_msg.alternate_generator = h;
  network_driver->send(
    crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &h_msg)
  );

  // Receive message from prover
  auto prover_msg_data_and_ok = crypto_driver->decrypt_and_verify(
    AES_key, HMAC_key, network_driver->read()
  );
  if (!prover_msg_data_and_ok.second) {
    network_driver->disconnect();
    throw std::runtime_error("Failed to decrypt and verify prover message");
  }

  // Deserialize prover message
  ProverToVerifier_NIZK_Message prover_msg;
  prover_msg.deserialize(prover_msg_data_and_ok.first);

  // Verify commitments for public wires
  for (size_t i = 0; i < this->circuit.public_input_length; i++) {
    if (prover_msg.openings[i].value != public_input[i] ||
        !crypto_driver->pedersen_verify(prover_msg.openings[i], h)) {
      network_driver->disconnect();
      return false;
    }
  }

  auto out_commit = prover_msg.commitments[this->circuit.num_wire - 1];
  auto out_open = prover_msg.openings[this->circuit.num_wire - 1];

  if (out_open.value != 1 || !crypto_driver->pedersen_verify(out_open, h)) {
    network_driver->disconnect();
    return false;
  }

  // Verify ZKPs for every gate
  for (size_t i = 0; i < this->circuit.num_gate; i++) {
    Gate gate = circuit.gates[i];
    
    if  (!crypto_driver->disjunctZKP_verify(
          prover_msg.zkps[i], prover_msg.commitments[gate.lhs],
          prover_msg.commitments[gate.rhs],
          prover_msg.commitments[gate.output])
        ) {
      network_driver->disconnect();
      return false;
    }
  }

  return true;
}