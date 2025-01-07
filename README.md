⚠️ IMPORTANT ⚠️

Disclaimer and Ethical Use
This password-cracking tool is intended strictly for educational purposes and authorized security testing. It is designed to demonstrate the vulnerabilities of weak passwords and emphasize the importance of using strong, secure passwords in real-world applications. Unauthorized use of this tool to crack passwords, gain access to systems, or compromise user accounts without explicit permission is illegal and unethical. Always ensure you have the explicit consent of the system owner before conducting any password recovery or security testing. The developer does not condone misuse of this code and is not responsible for any consequences arising from improper or unauthorized use. Use responsibly and ethically, adhering to all relevant laws and guidelines.


Project Description
This project is a Password Cracker Tool that combines dictionary-based attacks and brute-force techniques to crack hashed passwords. It is designed to help users understand password vulnerabilities and improve security practices. The tool supports multiple hash types and provides options for using local or remote wordlists.

Key Features:

⭕ Hybrid Cracking:
Dictionary Attack: Uses a wordlist to attempt password matching.
Brute-Force Attack: Generates password combinations up to a user-defined length when the dictionary attack fails.

⭕ Hashing Algorithm Support:
Supports common hashing algorithms like PBKDF2, MD5, and SHA-256.

⭕ Wordlist Management:
Allows the use of local wordlist files or downloads wordlists from URLs.

⭕ Progress Tracking:
Displays progress during cracking using the tqdm library.

⭕ Customizable Brute-Force Parameters:
Users can define the maximum length of brute-force password attempts.

⭕ Interactive Command-Line Interface:
Provides a menu-based interface for setting parameters and starting the cracking process.

⭕ Validation and Error Handling:
Ensures valid inputs for hashing algorithms, wordlists, and other configurations.
Handles errors gracefully, such as invalid file paths or unsupported hash types.
This project demonstrates the importance of strong password security by showcasing the methods attackers might use to compromise weak passwords. It serves as an educational tool for security professionals and enthusiasts.
