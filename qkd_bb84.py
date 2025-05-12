import random

class BB84QKD:
    def __init__(self, num_bits=128):
        self.num_bits = num_bits
        self.bases = []
        self.qubits = []
        self.keys = []
        self.eavesdropping_detected = False

    def generate_random_bits(self):
        return [random.randint(0, 1) for _ in range(self.num_bits)]

    def generate_random_bases(self):
        return [random.choice(['+', 'x']) for _ in range(self.num_bits)]

    def encode_qubits(self, bits, bases):
        qubits = []
        for i in range(self.num_bits):
            if bases[i] == '+':  # Standard basis (0, 1)
                qubits.append(bits[i])
            else:  # Hadamard basis (superposition)
                qubits.append((bits[i] + 1) % 2)
        return qubits

    def measure_qubits(self, qubits, bases):
        measured_bits = []
        for i in range(self.num_bits):
            if bases[i] == '+':  # Measure in the standard basis
                measured_bits.append(qubits[i])
            else:  # Measure in the Hadamard basis
                measured_bits.append((qubits[i] + 1) % 2)
        return measured_bits

    def sift_keys(self, sender_bases, receiver_bases, sender_bits, receiver_bits):
        key = []
        for i in range(self.num_bits):
            if sender_bases[i] == receiver_bases[i]:
                key.append(sender_bits[i])
        return key

    def run_protocol(self):
        # Step 1: Sender generates random bits and bases
        sender_bits = self.generate_random_bits()
        sender_bases = self.generate_random_bases()

        # Step 2: Sender encodes bits into qubits based on bases
        qubits = self.encode_qubits(sender_bits, sender_bases)

        # Step 3: Receiver chooses random bases to measure qubits
        receiver_bases = self.generate_random_bases()

        # Step 4: Receiver measures qubits and generates raw key
        receiver_bits = self.measure_qubits(qubits, receiver_bases)

        # Step 5: Sender and receiver compare bases and generate the final key
        final_key = self.sift_keys(sender_bases, receiver_bases, sender_bits, receiver_bits)

        # Step 6: Detect eavesdropping (compare a subset of keys for discrepancies)
        eavesdropping_detected = self.detect_eavesdropping(sender_bits, receiver_bits, sender_bases, receiver_bases)

        return final_key, eavesdropping_detected

    def detect_eavesdropping(self, sender_bits, receiver_bits, sender_bases, receiver_bases):
        error_rate_threshold = 0.1  # Adjust as needed
        mismatches = 0
        matched_bases = 0

        for i in range(self.num_bits):
            if sender_bases[i] == receiver_bases[i]:
                matched_bases += 1
                if sender_bits[i] != receiver_bits[i]:
                    mismatches += 1

        error_rate = mismatches / matched_bases if matched_bases > 0 else 0
        if error_rate > error_rate_threshold:
            return True  # Eavesdropping detected
        return False  # No eavesdropping

# Example usage:
bb84 = BB84QKD()
key, eavesdrop_detected = bb84.run_protocol()

if eavesdrop_detected:
    print("Eavesdropping detected! Abort key exchange.")
else:
    print("Key exchange successful. Shared key:", key)
