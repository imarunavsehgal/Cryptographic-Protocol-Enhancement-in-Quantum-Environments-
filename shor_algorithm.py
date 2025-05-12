import numpy as np
import pennylane as qml

def gcd(a, b):
    """Calculate the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def order_finding(a, N):
    """Finds the order of a modulo N using quantum phase estimation."""
    num_qubits = 4  # Number of qubits for the quantum circuit
    dev = qml.device('default.qubit', wires=num_qubits + 1)

    @qml.qnode(dev)
    def circuit():
        # Initialize the first register (superposition)
        for i in range(num_qubits):
            qml.Hadamard(wires=i)

        # Add ancilla qubit
        qml.Hadamard(wires=num_qubits)

        # Apply controlled-U gates
        for i in range(num_qubits):
            qml.CRZ(2 * np.pi * (a ** (2 ** i) % N), wires=[i, num_qubits])

        # Apply inverse quantum Fourier transform
        for i in range(num_qubits // 2):
            qml.SWAP(wires=[i, num_qubits - 1 - i])
        for i in range(num_qubits):
            qml.Hadamard(wires=i)

        # Return the probabilities instead of samples
        return qml.probs(wires=range(num_qubits))

    # Run the circuit and return probabilities
    probabilities = circuit()
    return probabilities

def shors_algorithm(N):
    """Runs Shor's algorithm to factor the number N."""
    # Step 1: Classical preprocessing
    a = 2  # Randomly chosen coprime number to N
    gcd_value = gcd(a, N)
    
    if gcd_value != 1:
        print(f"Trivial factor found: {gcd_value}")
        return [gcd_value]

    # Step 2: Quantum order finding
    probabilities = order_finding(a, N)

    # Step 3: Classical postprocessing
    # Analyze probabilities to estimate the order
    print("Probabilities obtained from quantum circuit:", probabilities)

    return None

if __name__ == "__main__":
    N = 15  # Example number to factor
    factors = shors_algorithm(N)
    print(f"Factors of {N}: {factors}")
