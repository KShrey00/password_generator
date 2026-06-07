# Password Generator & Strength Analyzer

A Python command-line tool that generates cryptographically secure passwords and analyzes password strength using entropy calculations, character composition analysis, and estimated crack times.

## Features

- Generate cryptographically secure passwords using Python's `secrets` module
- Customize password length
- Include or exclude special characters
- Analyze existing passwords
- Calculate password entropy in bits
- Estimate password crack time
- Detect common password weaknesses:
  - Short passwords
  - Low character variety
  - Repeating characters
  - Sequential characters
  - Sequential numbers

## Technologies Used

- Python 3
- `secrets`
- `string`
- `math`
- `re`
- `sys`

## Installation

Clone the repository:

```bash
git clone https://github.com/{HHHHHHHHFGMHV}/password-generator.git
cd password-generator
```

No external dependencies are required.

## Usage

### Generate a Password

```bash
python passgen.py
```

Example Output:

```text
============================================================
Generated password: kA#9xM!2Lp@7
============================================================
Strength: VERY STRONG
Entropy: 78.66 bits
Length: 12 characters
Estimated crack time: 13 years

~~ No issues found!
```

---

### Generate a Password with Custom Length

```bash
python passgen.py --length 16
```

---

### Generate a Password Without Special Characters

```bash
python passgen.py --length 12 --no-special
```

---

### Check Password Strength

```bash
python passgen.py --check "MyPassword123!"
```

Example Output:

```text
============================================================
Password Analysis
============================================================
Password: MyPassword123!
Length: 14 characters
Strength: STRONG
Entropy: 91.75 bits
Estimated crack time: 45908 years
```

---

### Display Help

```bash
python passgen.py --help
```

## How It Works

### Password Generation

The tool uses Python's `secrets` module to generate cryptographically secure random passwords.

Character pools include:

- Uppercase letters (A-Z)
- Lowercase letters (a-z)
- Digits (0-9)
- Special characters

### Entropy Calculation

Password entropy is calculated using:

```text
Entropy = Password Length × log₂(Character Pool Size)
```

Higher entropy indicates a stronger password and a larger search space for attackers.

### Crack Time Estimation

The tool estimates the average time required to brute-force a password assuming:

```text
1,000,000,000 guesses per second
```

The estimate is based on:

```text
Average Crack Time = (2^Entropy) / Guesses Per Second / 2
```

### Weakness Detection

The analyzer identifies:

- Passwords shorter than 8 characters
- Insufficient character variety
- Repeated characters (e.g., aaa, 111)
- Sequential letters (e.g., abc, xyz)
- Sequential numbers (e.g., 123, 456)

## Example Commands

```bash
python passgen.py

python passgen.py --length 20

python passgen.py --length 16 --no-special

python passgen.py --check "SecureP@ssw0rd!"

python passgen.py --help
```

## Future Improvements

- Interactive menu mode
- Password history generation
- Export generated passwords
- Password breach checking using public APIs
- Custom character sets
- Password strength scoring system
- Unit testing

## Learning Objectives

This project was built to practice:

- Python programming
- Secure random number generation
- Regular expressions
- Command-line argument handling
- Entropy calculations
- Password security concepts
- Code organization and documentation

## License

This project is licensed under the MIT License.

## Author

Shreya Kumari

GitHub: https://github.com/KShrey00