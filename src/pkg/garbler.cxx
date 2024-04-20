#include <algorithm>
#include <crypto++/misc.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/garbler.hpp"

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
GarblerClient::GarblerClient(Circuit circuit,
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
GarblerClient::HandleKeyExchange() {
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
  this->ot_driver =
      std::make_shared<OTDriver>(network_driver, crypto_driver, keys);
  return keys;
}

/**
 * run. This function should:
 * 1) Generate a garbled circuit from the given circuit in this->circuit
 * 2) Send the garbled circuit to the evaluator
 * 3) Send garbler's input labels to the evaluator
 * 4) Send evaluator's input labels using OT
 * 5) Receive final labels, and use this to get the final output
 * `input` is the garbler's input for each gate
 * Final output should be a string containing only "0"s or "1"s
 * Throw errors only for invalid MACs
 */
std::string GarblerClient::run(std::vector<int> input) {
  // Key exchange
  auto keys = this->HandleKeyExchange();
  auto AES_key = keys.first;
  auto HMAC_key = keys.second;

  auto labels = generate_labels(circuit);
  auto gates = generate_gates(circuit, labels);

  // Send garbled circuit
  GarblerToEvaluator_GarbledTables_Message garbled_tables;
  garbled_tables.garbled_tables = gates;
  network_driver->send(
    crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &garbled_tables)
  );

  // Send garbler's input labels
  GarblerToEvaluator_GarblerInputs_Message garbler_inputs;
  garbler_inputs.garbler_inputs = get_garbled_wires(labels, input, 0);
  network_driver->send(
    crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &garbler_inputs)
  );

  // Send evaluator's input labels using OT
  std::vector<std::string> ot_outputs;
  int begin = circuit.garbler_input_length;
  for (int i = 0; i < circuit.evaluator_input_length; i++) {
    ot_driver->OT_send(
      byteblock_to_string(labels.zeros[i].value),
      byteblock_to_string(labels.ones[i].value)
    );
  }

  // Evaluator is evaluating...

  // Receive final labels
  auto final_labels_data_and_ok = crypto_driver->decrypt_and_verify(
    AES_key, HMAC_key, network_driver->read()
  );
  if (!final_labels_data_and_ok.second) {
    network_driver->disconnect();
    throw std::runtime_error("Invalid MAC");
  }
  EvaluatorToGarbler_FinalLabels_Message final_labels;
  final_labels.deserialize(final_labels_data_and_ok.first);

  // Get final output
  std::string final_output;
  begin = circuit.num_wire - circuit.output_length;
  for (int i = 0; i < circuit.output_length; i++) {
    auto label = final_labels.final_labels[i].value;
    if (label == labels.zeros[begin + i].value) {
      final_output += "0";
    } else if (label == labels.ones[begin + i].value) {
      final_output += "1";
    } else {
      std::cerr << "Invalid output label sent by evaluator to garbler." << std::endl;
    }
  }

  std::cout << "output: " << final_output << std::endl;
  return final_output;
}

/**
 * Generate garbled gates for the circuit by encrypting each entry.
 * You may find `std::random_shuffle` useful
 */
std::vector<GarbledGate> GarblerClient::generate_gates(Circuit circuit,
                                                       GarbledLabels labels) {
  auto gates = std::vector<GarbledGate>();

  for (auto &gate : circuit.gates) {
    GarbledGate garbled;
    switch (gate.type) {
      case GateType::AND_GATE:
        garbled.entries.push_back(encrypt_label(labels.zeros[gate.lhs], labels.zeros[gate.rhs], labels.zeros[gate.output]));
        garbled.entries.push_back(encrypt_label(labels.zeros[gate.lhs], labels.ones[gate.rhs], labels.zeros[gate.output]));
        garbled.entries.push_back(encrypt_label(labels.ones[gate.lhs], labels.zeros[gate.rhs], labels.zeros[gate.output]));
        garbled.entries.push_back(encrypt_label(labels.ones[gate.lhs], labels.ones[gate.rhs], labels.ones[gate.output]));
        break;
      case GateType::XOR_GATE:
        garbled.entries.push_back(encrypt_label(labels.zeros[gate.lhs], labels.zeros[gate.rhs], labels.zeros[gate.output]));
        garbled.entries.push_back(encrypt_label(labels.zeros[gate.lhs], labels.ones[gate.rhs], labels.ones[gate.output]));
        garbled.entries.push_back(encrypt_label(labels.ones[gate.lhs], labels.zeros[gate.rhs], labels.ones[gate.output]));
        garbled.entries.push_back(encrypt_label(labels.ones[gate.lhs], labels.ones[gate.rhs], labels.zeros[gate.output]));
        break;
      case GateType::NOT_GATE:
        garbled.entries.push_back(encrypt_label(labels.zeros[gate.lhs], {DUMMY_RHS}, labels.ones[gate.output]));
        garbled.entries.push_back(encrypt_label(labels.ones[gate.lhs], {DUMMY_RHS}, labels.zeros[gate.output]));
        break;
      default:
        std::cout << "This code should be unreachable, gate type invalid" << std::endl;
        std::abort();
    }
    std::random_shuffle(garbled.entries.begin(), garbled.entries.end());
    gates.push_back(garbled);
  }

  return gates;
}

/**
 * Generate labels for *every* wire in the circuit.
 * To generate an individual label, use `generate_label`.
 */
GarbledLabels GarblerClient::generate_labels(Circuit circuit) {
  GarbledLabels labels;
  for (int i = 0; i < circuit.num_wire; i++) {
    labels.zeros.push_back(GarbledWire{generate_label()});
    labels.ones.push_back(GarbledWire{generate_label()});
  }
  return labels;
}

/**
 * Generate the encrypted label given the lhs, rhs, and output of that gate.
 * Remember to tag LABEL_TAG_LENGTH trailing 0s to end before encrypting.
 * You may find CryptoDriver::hash_inputs, CryptoPP::SecByteBlock::CleanGrow,
 * and CryptoPP::xorbuf useful.
 */
CryptoPP::SecByteBlock GarblerClient::encrypt_label(GarbledWire lhs,
                                                    GarbledWire rhs,
                                                    GarbledWire output) {
  auto left = crypto_driver->hash_inputs(lhs.value, rhs.value);
  auto right = output.value;
  right.CleanGrow(right.size() + LABEL_TAG_LENGTH);
  assert(left.size() == right.size());
  SecByteBlock encrypted(right.size());
  CryptoPP::xorbuf(encrypted, left, right, right.size());
  return encrypted;
}

/**
 * Generate label.
 */
CryptoPP::SecByteBlock GarblerClient::generate_label() {
  CryptoPP::SecByteBlock label(LABEL_LENGTH);
  CryptoPP::OS_GenerateRandomBlock(false, label, label.size());
  return label;
}

/*
 * Given a set of 0/1 labels and an input vector of 0's and 1's, returns the
 * labels corresponding to the inputs starting at begin.
 */
std::vector<GarbledWire>
GarblerClient::get_garbled_wires(GarbledLabels labels, std::vector<int> input,
                                 int begin) {
  std::vector<GarbledWire> res;
  for (int i = 0; i < input.size(); i++) {
    switch (input[i]) {
    case 0:
      res.push_back(labels.zeros[begin + i]);
      break;
    case 1:
      res.push_back(labels.ones[begin + i]);
      break;
    default:
      std::cerr << "INVALID INPUT CHARACTER" << std::endl;
    }
  }
  return res;
}
