
# BB84 Quantum Key Distribution + AES Encryption Simulation

import hashlib
import numpy as np

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from qiskit import QuantumCircuit
from qiskit_aer import Aer


N = 100   # number of qubits
EVE_INTERCEPT = False   # True -> Eve 공격 시뮬레이션

class BB84:

    def __init__(self, n):
        self.n = n

        self.alice_bits = np.random.randint(2, size=n)
        self.alice_basis = np.random.randint(2, size=n)

        self.bob_basis = np.random.randint(2, size=n)

        self.measured_bits = None

        self.shared_key = None

    # ---------------------------
    # Alice prepares qubits
    # ---------------------------

    def prepare_qubits(self):

        circuit = QuantumCircuit(self.n, self.n)

        for i in range(self.n):

            if self.alice_bits[i] == 1:
                circuit.x(i)

            if self.alice_basis[i] == 1:
                circuit.h(i)

        return circuit


    # ---------------------------
    # Eve intercept (optional)
    # ---------------------------

    def eve_attack(self, circuit):

        if not EVE_INTERCEPT:
            return circuit

        eve_basis = np.random.randint(2, size=self.n)

        for i in range(self.n):

            if eve_basis[i] == 1:
                circuit.h(i)

        circuit.measure(range(self.n), range(self.n))

        simulator = Aer.get_backend("qasm_simulator")

        job = simulator.run(circuit, shots=1)
        result = job.result()

        counts = result.get_counts()

        measured = list(counts.keys())[0]

        new_circuit = QuantumCircuit(self.n, self.n)

        for i in range(self.n):

            bit = int(measured[self.n - i - 1])

            if bit == 1:
                new_circuit.x(i)

            if eve_basis[i] == 1:
                new_circuit.h(i)

        return new_circuit


    # ---------------------------
    # Bob measurement
    # ---------------------------

    def bob_measure(self, circuit):

        for i in range(self.n):

            if self.bob_basis[i] == 1:
                circuit.h(i)

        circuit.measure(range(self.n), range(self.n))

        simulator = Aer.get_backend("qasm_simulator")

        job = simulator.run(circuit, shots=1)
        result = job.result()

        counts = result.get_counts()

        measured = list(counts.keys())[0]

        self.measured_bits = np.array(
            [int(measured[self.n - i - 1]) for i in range(self.n)]
        )


    # ---------------------------
    # Sifting (basis matching)
    # ---------------------------

    def sift_key(self):

        key = []

        for i in range(self.n):

            if self.alice_basis[i] == self.bob_basis[i]:
                key.append(self.measured_bits[i])

        self.shared_key = key


    # ---------------------------
    # Error rate check
    # ---------------------------

    def error_rate(self):

        errors = 0
        total = 0

        for i in range(self.n):

            if self.alice_basis[i] == self.bob_basis[i]:

                total += 1

                if self.alice_bits[i] != self.measured_bits[i]:
                    errors += 1

        if total == 0:
            return 0

        return errors / total


    # ---------------------------
    # AES Encryption
    # ---------------------------

    def encrypt(self, message):

        key_str = "".join(map(str, self.shared_key))

        aes_key = hashlib.sha256(key_str.encode()).digest()[:16]

        cipher = AES.new(aes_key, AES.MODE_CBC)

        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

        return cipher.iv + ciphertext


    def decrypt(self, ciphertext):

        key_str = "".join(map(str, self.shared_key))

        aes_key = hashlib.sha256(key_str.encode()).digest()[:16]

        iv = ciphertext[:16]
        ct = ciphertext[16:]

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        plaintext = unpad(cipher.decrypt(ct), AES.block_size)

        return plaintext.decode()


# ---------------------------
# Run Simulation
# ---------------------------

bb84 = BB84(N)

circuit = bb84.prepare_qubits()

circuit = bb84.eve_attack(circuit)

bb84.bob_measure(circuit)

bb84.sift_key()

error = bb84.error_rate()

print("Error Rate:", error)

if error > 0.25:
    print("Eavesdropping detected! Key discarded.")
else:

    message = "Quantum cryptography is secure."

    ciphertext = bb84.encrypt(message)

    decrypted = bb84.decrypt(ciphertext)

    print("Original:", message)
    print("Decrypted:", decrypted)



