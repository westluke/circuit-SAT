#pragma once

#include "../../include-shared/circuit.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

class VerifierClient {
public:
  VerifierClient(Circuit circuit,
                  std::shared_ptr<NetworkDriver> network_driver,
                  std::shared_ptr<CryptoDriver> crypto_driver);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> HandleKeyExchange();
  bool run(std::vector<bool>);

private:
  Circuit circuit;
  std::shared_ptr<NetworkDriver> network_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<CLIDriver> cli_driver;
};
