#include <iostream>

#include "circuit.hpp"
#include "crypto++/sha.h"

/*
 * Parse circuit from file in Bristol format.
 */
Circuit parse_circuit(std::string filename) {
  Circuit circuit;

  // Open file, scan header.
  FILE *f = fopen(filename.c_str(), "r");
  (void)fscanf(f, "%d%d\n", &circuit.num_gate, &circuit.num_wire);

  // We now skip the third parameter, since the output length is always 1.
  (void)fscanf(f, "%d%d%*d\n", &circuit.public_input_length,
               &circuit.witness_input_length);
  (void)fscanf(f, "\n");

  // Scan gates.
  circuit.gates.resize(circuit.num_gate);
  int lhs, rhs, output;
  for (int i = 0; i < circuit.num_gate; ++i) {
    (void)fscanf(f, "%d%d%d", &lhs, &rhs, &output);
    circuit.gates[i] = {lhs, rhs, output};
  }

  std::cout << "Parsed circuit with " << circuit.num_gate << " gates and "
            << circuit.num_wire << " wires." << std::endl;
  std::cout << "Public input length: " << circuit.public_input_length
            << std::endl;
  std::cout << "Witness input length: " << circuit.witness_input_length;

  return circuit;
}
