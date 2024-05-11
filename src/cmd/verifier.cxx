#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/circuit.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/verifier.hpp"

/*
steps:
fully evaluate the circuit with our witness
IGNORE THE FACT THAT CLIENT KNOWS ABOUT PUBLIC VALUE.
Just construct ZKP for each gate. And send them all over.
Client verifies each ZKP.

For simplicity, we only use NAND gates.

what else must zkp receiver do?
Ah shit, sender can't have the same number of disjuncts in each proof.
For gates involving public component, must constrain, otherwise receiver doesn't know
that they used the right public component!

Also, sender must actually commit to all the true values, so it does have to fully evaluate
the circuit. So must slightly modify circuit setup.


OK so: sender fully evaluates circuit, storing actual value for each wire in array.
Sender sends message committing to each wire value, along with openings for input wires.
Receiver sends back random values for every gate.
Sender splits each random value into 4, using them for quadruple disjunction ZKP for each gate.
How do the AND zkps work? how exactly do we compose?

I think we can use the same randomness for each conjunct. Cuz they came from different commitments.

ok the individual zkps are basically just schnorr.



ugh ok think about this logically. you simulate 3 cases, do the last one for real, by splitting the challenge
into a sum of four parts.

For each fake case, you get to choose the challenge. That does mean you're proving 3 commitments with a single
challenge. But then you can't be choosing the challenge individually for each conjunct. OH but that's fine, because
you're still choosing the challenge ahead of time. Yeah that's fine.

Ok let's do it.



wait, why can't schnorr be simplified?

y = g^x. Receiver samples r, calculates g^r = A.
Sender calculates A^x = (g^r)^x = B, receiver verifies (y)^r = B

its complete and valid. Wait, is it valid? But there's no extractor. That's the problem.
So it must not be valid.... whatever.
*/

/*
 * Usage: ./circuit_prover <circuit file> <public_input_file> <address> <port>
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger(logging::trivial::severity_level::trace);

  // Parse args
  if (!(argc == 5)) {
    std::cout << "Usage: ./circuit_prover <circuit file> <public_input_file> <address> <port>"
              << std::endl;
    return 1;
  }
  std::string circuit_file = argv[1];
  std::string address = argv[3];
  int port = atoi(argv[4]);

  // Parse circuit.
  Circuit circuit = parse_circuit(circuit_file);

  // Parse public input (to be proved can satisfy circuit)
  std::vector<bool> public_input = parse_input(argv[2]);

  // Connect to network driver.
  std::shared_ptr<NetworkDriver> network_driver =
      std::make_shared<NetworkDriverImpl>();
  network_driver->connect(address, port);
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();

  // Create garbler then run.
  VerifierClient verifier =
      VerifierClient(circuit, network_driver, crypto_driver);
  if (verifier.run(public_input)) {
    std::cout << "ZKP verified" << std::endl;
  } else {
    std::cout << "ZKP failed" << std::endl;
  }
  return 0;
}
