#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/circuit.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/prover.hpp"

/*
 * Usage: ./circuit_prover <circuit file> <input file> <address> <port>
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger(logging::trivial::severity_level::trace);

  // Parse args
  if (!(argc == 6)) {
    std::cout
        << "Usage: ./circuit_prover <circuit file> <public input file> <witness file> <address> <port>"
        << std::endl;
    return 1;
  }
  std::string circuit_file = argv[1];
  std::string input_file = argv[2];
  std::string witness_file = argv[3];
  std::string address = argv[4];
  int port = atoi(argv[5]);

  // Parse circuit.
  Circuit circuit = parse_circuit(circuit_file);

  // Parse input.
  std::vector<bool> input = parse_input(input_file);

  // Parse input.
  std::vector<bool> witness = parse_input(witness_file);

  // Connect to network driver.
  std::shared_ptr<NetworkDriver> network_driver =
      std::make_shared<NetworkDriverImpl>();
  network_driver->listen(port);
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();

  // Create garbler then run.
  ProverClient prover = ProverClient(circuit, network_driver, crypto_driver);
  prover.run(input, witness);
  return 0;
}
