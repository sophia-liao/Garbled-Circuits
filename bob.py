import pickle
from copy import deepcopy
from Crypto.Hash import SHA256
from Crypto.Cipher import Salsa20
from elgamal.elgamal import Elgamal


# 4-bit string represents gate's output for inputs 00, 01, 10, 11
# you can add your own gates to this dict
gate_lookup = {
    ">": "0010",
    "==": "1001",
    ">=": "1011",
    "and": "0001",
    "or": "0111"
}

# Bob generates one fake key and one real key in arithmetic progression
def bob_ot1(bit):
    pk, sk = Elgamal.newkeys(128)
    pk2 = deepcopy(pk)

    # public keys form arithmetic progression with d=1
    if bit:
        pk2.y -= 1
        return (pk2, pk), sk
    else:
        pk2.y += 1
        return (pk, pk2), sk


# Bob decrypts his desired password
def bob_ot2(bit, bob_sk, alice_ciphertexts):
    enc_msg = alice_ciphertexts[bit]
    return bytes(Elgamal.decrypt(enc_msg, bob_sk))


# evaluates P_out of a garbled gate (dict with 4 entries)
def evaluate(garbled_gate, P_left, P_right):
    P = P_left + P_right
    hP = SHA256.new(data=P).digest()

    # choose nonce to be truncated hash, since it is only used once
    nonce = hP[:8]
    cipher = Salsa20.new(P, nonce)
    enc = garbled_gate[hP]
    return cipher.decrypt(enc)


# evaluates entire garbled gates circuit and prints outcome
def eval_circuit(garbled_gates):
    stack = []
    func = garbled_gates["func"]

    for i, var in enumerate(func):
        is_final = (i == len(func) - 1)
        if var in gate_lookup:
            g_name = f"{gate_lookup[var]}_{i}"

            # pop reverses direction
            i2 = stack.pop()
            i1 = stack.pop()

            # evaluates a single garbled gate
            P_left = i1
            P_right = i2
            P_out = evaluate(garbled_gates[g_name], P_left, P_right)

            if not is_final:
                stack.append(P_out)
            else:
                if P_out == b"00000000":
                    print("Outcome is 0")

                    # only for millionaire's problem
                    if func == ["a1", "b1", ">", "a1", "b1", "==", "a0", "b0", ">=", "and", "or"]:
                        print("Bob's value is larger than Alice's")
                else:
                    print("Outcome is 1")

                    # only for millionaire's problem
                    if func == ["a1", "b1", ">", "a1", "b1", "==", "a0", "b0", ">=", "and", "or"]:
                        print("Alice's value is at least as large as Bob's")
        else:
            # if var is an input, we just add it to the stack
            stack.append(garbled_gates[var])

    # if func is valid, the stack should be empty
    assert len(stack) == 0



def bob_main(b):
    # isolate b1 and b0 from b
    b1 = (b >> 1) & 1
    b0 = b & 1

    # give Alice real/fake keys for b1 and b0
    (pk_1, pk2_1), sk_1 = bob_ot1(b1)
    (pk_0, pk2_0), sk_0 = bob_ot1(b0)
    
    bob_request = {"b1": (pk_1, pk2_1), "b0": (pk_0, pk2_0)}
    with open("bob_request.pkl", "wb") as f:
        pickle.dump(bob_request, f)

    # wait for Alice to give encrypted passwords for b1 and b0
    # wait for Alice to give garbled gates
    input("Press enter after Alice generates alice_reply.pkl and garbled_gates.pkl")

    with open("alice_reply.pkl", "rb") as f:
        alice_reply = pickle.load(f)
    with open("garbled_gates.pkl", "rb") as f:
        garbled_gates = pickle.load(f)

    garbled_gates["b1"] = bob_ot2(b1, sk_1, alice_reply["b1"])
    garbled_gates["b0"] = bob_ot2(b0, sk_0, alice_reply["b0"])

    eval_circuit(garbled_gates)



# input can be any 2-bit integer (from 0 to 3)
bob_main(0)
