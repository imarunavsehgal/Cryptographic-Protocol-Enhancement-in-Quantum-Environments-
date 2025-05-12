# Cryptographic-Protocol-Enhancement-in-Quantum-Environments-

The field of cryptography is the foundation of secure communication in the digital age. Public-key 
cryptosystems, like RSA and ECC, ensure data confidentiality, integrity, and validity in diverse 
applications like online banking, secure email, and e-commerce transactions. These systems rely on 
hard mathematical issues that are computationally difficult to answer, giving a strong foundation for 
secure communications. However, as quantum computing advances at a rapid pace, several widely used 
cryptographic algorithms face significant risks to the security of sensitive data. 
Shor's algorithm, once operational on a large-scale quantum computer, has the potential to break these 
cryptographic systems by efficiently factoring large integers or solving discrete logarithm problems—
 tasks that classical computers cannot achieve at the same speed [1]. This paradigm change threatens to 
render present cryptographic procedures outdated, thus researchers and practitioners must devise 
strategies to limit the hazards posed by quantum developments. 
In response to this existential threat, our project aims to create a dynamic evaluation tool for assessing 
the vulnerability of network communications to quantum crypto attacks. The PQC Attack Resistance 
Evaluator analyses current network traffic and archived packet capture (PCAP) files, assigns quantum
safe scores to communication protocols, and recommends remedial steps [2]. This technology not only 
finds vulnerabilities, but it also prioritises them depending on the level of danger they pose, allowing 
organisations to concentrate their attention on the most important issues. It also includes technologies 
like RSA key size augmentation and QKD, which allow users to efficiently reinforce their cryptographic 
defences. This technique tries to make network communications immune to both current classical 
attacks and future quantum attacks.

The main goals of this initiative are as follows:  
1. Develop a Protocol Evaluation Tool: Evaluate cryptographic protocols' quantum resistance in 
real-time using packet capture data and network traffic. 
2. RSA Key Size Enhancement: Create a module to check and upgrade RSA key sizes to 4096 bits 
if they are below the quantum-safe threshold. 
3. Integrate Quantum Key Distribution protocols (e.g., BB84) for safe key exchange against 
quantum attacks.  
4. Propose short and long-term mitigation measures for strengthening cryptographic protocols, 
including classical and quantum-safe methods.  
5. Stay current with post-quantum cryptography standards to ensure future proofing.

The Network Traffic Packet Collection/Sniffing module is the foundation of the PQC Attack Resistance 
Evaluator. This module captures, filters, and processes packets from both pre-recorded.cap files and 
live network interfaces. The primary purpose is to capture and analyse traffic in real time while finding 
encryption techniques and potential vulnerabilities. The packet capture method is built using programs 
such as Scapy and Pyshark, which can handle enormous volumes of network data in real-time [9], [10]. 
1. Packet Capture: The packet capture functionality is intended to capture network packets from 
several layers of the OSI model and categorise them according to user-defined characteristics. 
It employs pre-recorded.cap files and live traffic from network interfaces to ensure flexibility in 
data collection [10]. The module collects data from several network layers, including the 
transport and application layers  
2. Packet Categorisation: After capturing packets, the module categorises them by extracting 
crucial parameters such source and destination IP addresses, protocols, encryption techniques, 
and relevant metadata [11]. The categorisation distinguishes between encrypted and non
encrypted communications, allowing the system to discover weak encryption methods or 
unencrypted messages. This categorisation is necessary for the Protocol Checker's subsequent 
examination.  
3. Data Processing: The next step is to process the packet data for further investigation. After 
categorisation, packets are normalised to maintain consistency in data supplied to the assessment 
module [10]. Data normalisation is critical for correct protocol evaluation because information 
obtained from various network layers must be standardised to provide reliable comparison to 
quantum-safe norms. The system ensures that collected packets are processed in a timely and 
effective manner. This phase ensures that any protocol's cryptographic posture may be 
effectively assessed within the larger context of post-quantum security.  
This Python module effectively captures, filters, and processes packets. The integration of Pyshark with 
Scapy enables for real-time monitoring and analysis of archived.cap files, making the system flexible 
to varied network contexts. This thorough approach ensures that the PQC Attack Resistance Evaluator 
covers all essential components of network communications and finds cryptographic flaws that could 
be exploited by quantum assaults.
