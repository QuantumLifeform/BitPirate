A small python script that is doing the following things:

1. Asks user about bitrange in which the private key will be randomly generated
2. Generates random bitcoin addresses (both compressed and uncompressed)
3. Checks through blockchain API if they had transaction history
4. If they had transaction history it saves the address and it's private key to file (you can change the path in the code for your needs)
