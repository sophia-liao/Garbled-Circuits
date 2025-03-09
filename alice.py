import os
import pickle
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


# function expressed in reverse polish notation
# you can modify this function as you like
# a1 is the left bit/a0 is the right bit of Alice's value
# b1 is the left bit/b0 is the right bit of Bob's value
func = ["a1", "b1", ">", "a1", "b1", "==", "a0", "b0", ">=", "and", "or"]



# Alice encrypts both passwords based on Bob's fake and real key
def alice_ot1(bob_keys, msg0, msg1):
    pk, pk2 = bob_keys
    if pk2.y != pk.y + 1:
        raise Exception("Invalid key pair")

    return Elgamal.encrypt(msg0, pk), Elgamal.encrypt(msg1, pk2)


# creates a garbled gate as a 4-value dictionary:
#   keys: hashed concatenated passwords
#   values: encrypted output passwords
def garble(gate, passwords):
    # gate is a binary string of length 4
    # passwords are each 8 bytes

    P_out0, P_out1, P_left0, P_left1, P_right0, P_right1 = passwords

    # concatenate passwords to create 4 choices
    P00 = P_left0 + P_right0
    P01 = P_left0 + P_right1
    P10 = P_left1 + P_right0
    P11 = P_left1 + P_right1

    # hash concatenated passwords; Bob will see this
    hP00 = SHA256.new(data=P00).digest()
    hP01 = SHA256.new(data=P01).digest()
    hP10 = SHA256.new(data=P10).digest()
    hP11 = SHA256.new(data=P11).digest()

    # choose nonce to be truncated hash, since it is only used once
    nonce00 = hP00[:8]
    nonce01 = hP01[:8]
    nonce10 = hP10[:8]
    nonce11 = hP11[:8]

    # symmetric key encryption of P_out with concatenated passwords as key
    d = {"0": P_out0, "1": P_out1}
    enc00 = bytes(Salsa20.new(P00, nonce00).encrypt(d[gate[0]]))
    enc01 = bytes(Salsa20.new(P01, nonce01).encrypt(d[gate[1]]))
    enc10 = bytes(Salsa20.new(P10, nonce10).encrypt(d[gate[2]]))
    enc11 = bytes(Salsa20.new(P11, nonce11).encrypt(d[gate[3]]))

    return {hP00: enc00, hP01: enc01, hP10: enc10, hP11: enc11}


# Alice generates dictionary of secret passwords for all gates (ungarbled)
#   keys: gate names (ex: "0001_8" is an AND gate and the 9th encountered gate)
#         input names (ex: "a1")
#   values: 6-tuple (P_out0, P_out1, P_left0, P_left1, P_right0, P_right1)
def gen_passwords(func):
    # dictionary of passwords for all gates and inputs
    secret_pwds = {}
    stack = []

    for i, var in enumerate(func):
        is_final = (i == len(func) - 1)
        if var in gate_lookup:
            g_name = f"{gate_lookup[var]}_{i}"

            # pop reverses direction
            i2 = stack.pop()
            i1 = stack.pop()

            # if i1/i2 gate, take output passwords; otherwise, just take both passwords
            left = secret_pwds[i1][:2]
            right = secret_pwds[i2][:2]

            if not is_final:
                # first two values are P_out0, P_out1
                # each gate needs 2 randomly generated output passwords
                secret_pwds[g_name] = (os.urandom(8), os.urandom(8), left[0], left[1], right[0], right[1])
                stack.append(g_name)
            else:
                # the last gate outputs 0 or 1 instead of P_out
                secret_pwds[g_name] = (b"00000000", b"11111111", left[0], left[1], right[0], right[1])
        else:
            # generate random passwords for a1, a0, b1, b0
            if var not in secret_pwds:
                secret_pwds[var] = (os.urandom(8), os.urandom(8))
            stack.append(var)
    
    # if func is valid, the stack should be empty
    assert len(stack) == 0
    return secret_pwds


# Alice publishes the function, her passwords and all garbled gates
def publish_gates(a, secret_pwds, func):
    d = {}

    # publish function
    d["func"] = func

    # publish a's bits
    d["a1"] = secret_pwds["a1"][(a >> 1) & 1]
    d["a0"] = secret_pwds["a0"][a & 1]

    # publish gates
    for key, value in secret_pwds.items():
        # make sure key is a gate
        if len(value) != 6:
            continue
        d[key] = garble(key[:4], value)

    with open("garbled_gates.pkl", "wb") as f:
        pickle.dump(d, f)



def alice_main(a):
    secret_pwds = gen_passwords(func)

    # wait for Bob to give real/fake keys for b1 and b0
    input("Press enter after Bob generates bob_request.pkl")

    # give Bob encrypted (real/fake) passwords for b1 and b0
    alice_reply = {}
    with open("bob_request.pkl", "rb") as f:
        bob_request = pickle.load(f)
        for key, value in bob_request.items():
            msg0, msg1 = secret_pwds[key]
            r0, r1 = alice_ot1(value, msg0, msg1)
            alice_reply[key] = (r0, r1)
    
    with open("alice_reply.pkl", "wb") as f:
        pickle.dump(alice_reply, f)
    
    # give Bob the garbled gates
    publish_gates(a, secret_pwds, func)



# input can be any 2-bit integer (from 0 to 3)
alice_main(1)
