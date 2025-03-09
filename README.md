# Garbled Circuits

## Overview
Implementation of Garbled Circuits for 2-bit values on an arbitrary function.

## Usage
### Running files
Alice and Bob communicate by writing separate ```.pkl``` files.

* Run ```alice.py``` and ```bob.py``` on separate terminals.
* Once Bob generates ```bob_request.pkl```, press enter on Alice's terminal. (This will take a few seconds. We know this happens once Bob prompts "Press enter after Alice generates alice_reply.pkl and garbled_gates.pkl".)
* Once Alice generates ```alice_reply.pkl``` and ```garbled_gates.pkl```, press enter on Bob's terminal.
* Bob will print the outcome in his terminal.

### Modifying parameters
To run different inputs ```a``` and ```b```, modify the inputs to the functions ```alice_main()``` and ```bob_main()```.

Edit the variable ```func``` in ```alice.py``` to modify the function (it is currently set as $\geq$, i.e. Yao's Millionaire's Problem). The function is expressed in reverse Polish notation, where ```a1``` and ```a0``` refer to Alice's bits, ```b1``` and ```b0``` refer to Bob's bits, and other elements such as ```"=="``` refer to gate names, which can be looked up in the dictionary ```gate_lookup```. If you need to specify more gates, go ahead and add them to ```gate_lookup```.

## Details
I spent about 5-6 hours on this exercise.
