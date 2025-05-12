# protocol_checker.py
import os
import json
from scapy.all import rdpcap
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rsa_key_manager import RSAKeyManager  # Importing the RSAKeyManager
import pkgGlobal as gv
from qkd_bb84 import BB84QKD
from shor_algorithm import ShorsAlgorithm 


class ProtocolChecker(object):
    def __init__(self, db_link, db_type='json', debug_flag=False):
        self.score_dict = None
        if db_type == 'json' and os.path.exists(db_link):
            with open(db_link) as fh:
                self.score_dict = json.loads(fh.read())
        else:
            print("Init Error: Cannot find the QS-score JSON file.")
        self.debug_md = debug_flag
        if self.debug_md:
            print("Loaded the protocol JSON file: ")
            print(self.score_dict)

    def match_score(self, compare_dict):
        if not self.score_dict:
            return 0.0
        conf_val = 0
        pck_count = 0
        for c_key, val in compare_dict.items():
            temp_val = 0
            pck_count += val
            if gv.NTE_TAG in c_key:
                temp_val = 0
            else:
                for pro_k in self.score_dict[gv.LAYER_A_TAG].keys():
                    if pro_k in c_key and self.score_dict[gv.LAYER_A_TAG][pro_k] > temp_val:
                        temp_val = self.score_dict[gv.LAYER_A_TAG][pro_k]
            conf_val += temp_val * val
        final_score = float(conf_val) / pck_count if pck_count != 0 else conf_val
        return final_score

    def extract_rsa_key_size(self, protocol_data):
        packets = rdpcap(protocol_data)
        for packet in packets:
            if packet.haslayer('TLS') and packet['TLS'].haslayer('TLS Record'):
                record_layer = packet['TLS Record']
                if record_layer.haslayer('TLS Handshake'):
                    handshake_layer = record_layer['TLS Handshake']
                    if handshake_layer.haslayer('TLS Certificate'):
                        cert_layer = handshake_layer['TLS Certificate']
                        cert_data = cert_layer.load_certificate()
                        if cert_data:
                            try:
                                cert = None
                                try:
                                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                                except ValueError:
                                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                                if cert:
                                    public_key = cert.public_key()
                                    if isinstance(public_key, rsa.RSAPublicKey):
                                        return public_key.key_size
                            except Exception as e:
                                print(f"Error extracting RSA key: {e}")
        return 0

    def check_rsa_key_size(self, protocol_data):
        MIN_RSA_KEY_SIZE = 4096
        rsa_key_size = self.extract_rsa_key_size(protocol_data)
        if rsa_key_size < MIN_RSA_KEY_SIZE:
            print(f"RSA key size is {rsa_key_size} bits. Running Shor's Algorithm to simulate quantum attack...")
            self.run_shors_algorithm_simulation(rsa_key_size)
            RSAKeyManager.upgrade_rsa_key_size()  # Generate a 4096-bit key after Shor's attack simulation
            return False, f"RSA key size is {rsa_key_size} bits. Consider upgrading to at least {MIN_RSA_KEY_SIZE} bits for enhanced security."
        else:
            return True, f"RSA key size is {rsa_key_size} bits, which is adequate for short-term quantum resistance."
    
    def run_shors_algorithm_simulation(self, rsa_key_size):
        """
        Run Shor's algorithm simulation.
        """
        # Example: Factor a simple number (you can replace this with the actual RSA modulus)
        number_to_factor = 15  # This should ideally be the RSA modulus
        shor = ShorsAlgorithm(number_to_factor)
        factors = shor.run()

        if factors:
            print(f"Shor's algorithm found the factors: {factors}")
        else:
            print("Shor's algorithm failed to factor the number.")

    def analyze_protocol(self, protocol_data, compare_dict):
        score = self.match_score(compare_dict)
        print(f"Protocol score: {score}")
        rsa_key_check, rsa_message = self.check_rsa_key_size(protocol_data)
        print(rsa_message)
        self.run_qkd_protocol()

    def run_qkd_protocol(self):
        bb84 = BB84QKD(num_bits=128)  
        key, eavesdrop_detected = bb84.run_protocol()
        
        if eavesdrop_detected:
            print("Eavesdropping detected during key exchange.")
        else:
            print("Key exchange successful. Shared key:", key)

def test_case():
    checker = ProtocolChecker("C:\\Users\\Amolik Singh\\Desktop\\Network_PQC_Attack_Resistance_Evaluator-main\\src\\ProtocolRef.json", debug_flag=True)
    test_compare_dict = {
        'notEncript': 5,
        'Layer WG': 13,
        'DATALayer TLS': 3,
        'TLSv1 Record Layer: Handshake Protocol: Multiple Handshake Messages': 2,
        'TLSv1 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec': 2,
        'TLSv1 Record Layer: Handshake Protocol: Encrypted Handshake Message': 2,
        'TLSv1 Record Layer: Application Data Protocol: ldap': 9
    }
    protocol_data = "C:\\Users\\Amolik Singh\\Desktop\\Network_PQC_Attack_Resistance_Evaluator-main\\src\\test_SSHv1.pcap"  
    checker.analyze_protocol(protocol_data, test_compare_dict)
    RSAKeyManager.upgrade_rsa_key_size()  # Call the RSA key upgrade method

if __name__ == '__main__':
    test_case()
