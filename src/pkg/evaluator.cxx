#include "../../include/pkg/evaluator.hpp"
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

/**
 * Constructor. Note that the OT_driver is left uninitialized.
 */
EvaluatorClient::EvaluatorClient(Circuit circuit,
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
EvaluatorClient::HandleKeyExchange() {
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
  this->ot_driver =
      std::make_shared<OTDriver>(network_driver, crypto_driver, keys);
  return keys;
}

std::string gate_type_to_string(GateType::T type) {
  switch (type) {
    case GateType::AND_GATE:
      return "AND_GATE";
    case GateType::XOR_GATE:
      return "XOR_GATE";
    case GateType::NOT_GATE:
      return "NOT_GATE";
    default:
      return "UNKNOWN_GATE";
  }
}

/**
 * run. This function should:
 * 1) Receive the garbled circuit and the garbler's input
 * 2) Reconstruct the garbled circuit and input the garbler's inputs
 * 3) Retrieve evaluator's inputs using OT
 * 4) Evaluate gates in order (use `evaluate_gate` to help!)
 * 5) Send final labels to the garbler
 * 6) Receive final output
 * `input` is the evaluator's input for each gate
 * You may find `resize` useful before running OT
 * You may also find `string_to_byteblock` useful for converting OT output to
 * wires Disconnect and throw errors only for invalid MACs
 */
std::string EvaluatorClient::run(std::vector<int> input) {
  // Key exchange
  auto keys = this->HandleKeyExchange();
  auto AES_key = keys.first;
  auto HMAC_key = keys.second;

  // Receive garbled circuit
  auto circuit_data_and_ok = crypto_driver->decrypt_and_verify(
      AES_key, HMAC_key, network_driver->read()
  );
  if (!circuit_data_and_ok.second) {
    network_driver->disconnect();
    throw std::runtime_error("Invalid MAC");
  }
  GarblerToEvaluator_GarbledTables_Message garbled_tables;
  garbled_tables.deserialize(circuit_data_and_ok.first);
  auto garbled_gates = garbled_tables.garbled_tables;

  // Receive garbler's input
  auto garbler_input_data_and_ok = crypto_driver->decrypt_and_verify(
      AES_key, HMAC_key, network_driver->read()
  );
  if (!garbler_input_data_and_ok.second) {
    network_driver->disconnect();
    throw std::runtime_error("Invalid MAC");
  }
  GarblerToEvaluator_GarblerInputs_Message garbler_inputs;
  garbler_inputs.deserialize(garbler_input_data_and_ok.first);
  // assert(garbler_inputs.garbler_inputs.size() == circuit.garbler_input_length);

  std::cout << "Starting OT..." << std::endl;

  // Retrieve labels for our inputs
  std::vector<GarbledWire> evaluated_wires = garbler_inputs.garbler_inputs;
  evaluated_wires.resize(circuit.num_wire);
  for (int i = 0; i < input.size(); i++) {
    auto ot_output = ot_driver->OT_recv(input[i]);
    evaluated_wires[circuit.garbler_input_length + i].value = string_to_byteblock(ot_output);
  }

  std::cout << "Finished OT, starting circuit evaluation..." << std::endl;
  // assert(evaluated_wires.size() == circuit.garbler_input_length + circuit.evaluator_input_length);

  // Evaluate circuit
  // evaluated_wires.resize(circuit.num_wire);
  for (int i = 0; i < circuit.num_gate; i++) {
    auto lhs = evaluated_wires[circuit.gates[i].lhs];
    // assert(!lhs.value.empty());
    GarbledWire rhs;
    if (circuit.gates[i].type == GateType::NOT_GATE) {
      rhs = {DUMMY_RHS};
    } else {
      rhs = evaluated_wires[circuit.gates[i].rhs];
      // assert(!rhs.value.empty());
    }
    auto output = evaluate_gate(garbled_gates[i], lhs, rhs);
    // if (output.value.empty()) {
    //   std::cout << "gate evaluation failed, gate type was: " << gate_type_to_string(gate.type) << std::endl;
    // } else {
    //   std::cout << "SUCCESS, type: " << gate_type_to_string(gate.type) << std::endl;
    // }
    evaluated_wires[circuit.gates[i].output] = output;
  }

  std::cout << "Finished circuit evaluation, sending final labels..." << std::endl;

  // Send final labels
  EvaluatorToGarbler_FinalLabels_Message final_labels;
  final_labels.final_labels.resize(circuit.output_length);
  for (int i = 0; i < circuit.output_length; i++) {
    // assert(!evaluated_wires[i].value.empty());
    final_labels.final_labels[i] = evaluated_wires[circuit.num_wire - circuit.output_length + i];
  }
  // assert(final_labels.final_labels.size() == circuit.output_length);
  network_driver->send(
    crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &final_labels)
  );

  std::cout << "Finished sending final labels, waiting on final output..." << std::endl;

  // Receive final output
  auto final_output_data_and_ok = crypto_driver->decrypt_and_verify(
      AES_key, HMAC_key, network_driver->read()
  );
  if (!final_output_data_and_ok.second) {
    network_driver->disconnect();
    throw std::runtime_error("Invalid MAC");
  }
  GarblerToEvaluator_FinalOutput_Message final_output;
  final_output.deserialize(final_output_data_and_ok.first);
  return final_output.final_output;
}

/**
 * Evaluate gate.
 * You may find CryptoPP::xorbuf and CryptoDriver::hash_inputs useful.
 * To determine if a decryption is valid, use verify_decryption.
 * To retrieve the label from a decryption, use snip_decryption.
 */
GarbledWire EvaluatorClient::evaluate_gate(GarbledGate gate, GarbledWire lhs,
                                           GarbledWire rhs) {
  auto left = crypto_driver->hash_inputs(lhs.value, rhs.value);
  auto outbuf = CryptoPP::SecByteBlock(left.size());
  // assert(left.size() == LABEL_LENGTH + LABEL_TAG_LENGTH);
  // assert(lhs.value.size() == LABEL_LENGTH);

  for (auto &entry : gate.entries) {
    // assert(entry.size() == left.size());
    CryptoPP::xorbuf(outbuf, entry, left, left.size());
    if (verify_decryption(outbuf)) {
      return {snip_decryption(outbuf)};
    }
  }

  return GarbledWire();
}

/**
 * Verify decryption. A valid dec should end with LABEL_TAG_LENGTH bits of 0s.
 */
bool EvaluatorClient::verify_decryption(CryptoPP::SecByteBlock decryption) {
  CryptoPP::SecByteBlock trail(decryption.data() + LABEL_LENGTH,
                               LABEL_TAG_LENGTH);
  return byteblock_to_integer(trail) == CryptoPP::Integer::Zero();
}

/**
 * Returns the first LABEL_LENGTH bits of a decryption.
 */
CryptoPP::SecByteBlock
EvaluatorClient::snip_decryption(CryptoPP::SecByteBlock decryption) {
  CryptoPP::SecByteBlock head(decryption.data(), LABEL_LENGTH);
  return head;
}
