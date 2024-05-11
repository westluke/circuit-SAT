#pragma once

#include <fstream>
#include <stdio.h>
#include <string>
#include <vector>

#include <crypto++/cryptlib.h>
#include <crypto++/integer.h>
#include <crypto++/secblock.h>

// ================================================
// CIRCUIT TEMPLATE
// ================================================

// They're all NAND gates.
struct Gate {
  int lhs;    // index corresponding to lhs wire
  int rhs;    // index corresponding to rhs wire
  int output; // index corresponding to output wire
};

struct Circuit {
  int num_gate, num_wire, public_input_length, witness_input_length;
  std::vector<Gate> gates;
};
Circuit parse_circuit(std::string filename);