import secrets
import string 
import sys
import math
import re


def format_time(seconds):
    units = [
        ("second", 60),
        ("minute", 60),
        ("hour", 24),
        ("day", 365),
        ("year", None)
    ]

    value = seconds

    for unit, limit in units:
        if limit is None or value < limit:
            return f"{int(value)} {unit}{'' if int(value) == 1 else 's'}"
        value /= limit

def estimate_crack_time(entropy_bits):
    # estimate how long it will take to crack password

    #assuming 1 billion guesses per second (modern GPU)
    guesses_per_second = 1000000000

    #average crack time = 2^entropy / guesses_per_second / 2 (need 50%)
    seconds_to_crack = (2 ** entropy_bits) / guesses_per_second /2

    #convert to readable format
    return format_time(seconds_to_crack)

    
def calculate_entropy(password, character_pool_size):
    """
    calculate password entropy in bits
    entropy = ln(pool_size^password_length)
    args:
    password(str): Password to analyze
    character_pool_size(int): number of possible characters
    returns:
    float: entropy in bits
    """
    password_length = len(password)
    entropy = password_length * math.log2(character_pool_size)
    return entropy
    
def check_password_strength(password):
    """
    analyze password strength
    returns:
        dict: strength analysis
    """
    analysis = {
        'password': password,
        'length': len(password),
        'has_uppercase': bool(re.search(r'[A-Z]', password)),
        'has_lowercase': bool(re.search(r'[a-z]', password)),
        'has_digits': bool(re.search(r'[0-9]', password)),
        'has_special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password)),
        'issues': []
    }

    #count character types
    character_types = sum([
        analysis['has_uppercase'],
        analysis['has_lowercase'],
        analysis['has_digits'],
        analysis['has_special'],
    ])

    # estimate pool size used
    pool_size = 0
    if analysis['has_uppercase']:
        pool_size += 26
    if analysis['has_lowercase']:
        pool_size += 26
    if analysis['has_digits']:
        pool_size += 10
    if analysis['has_special']:
        pool_size += 32

    # calculate entropy
    analysis['entropy'] = (
        calculate_entropy(password, pool_size)
        if pool_size > 0
        else 0
    )

    # determine strength based on entropy
    if analysis['entropy'] < 30:
        analysis['strength'] = 'VERY WEAK'
    elif analysis['entropy'] < 50:
        analysis['strength'] = 'WEAK'
    elif analysis['entropy'] < 70:
        analysis['strength'] = 'MEDIUM'
    elif analysis['entropy'] < 90:
        analysis['strength'] = 'STRONG'
    else:
        analysis['strength'] = 'VERY STRONG'

    #identify issues
    if analysis['length'] < 8:
        analysis['issues'].append("Too short (< 8 characters)")
    
    if character_types < 3:
        analysis['issues'].append(
            f"Lacks variety ({character_types} character types, need 3+)"
        )
    if re.search(r'(.)\1{2,}', password):  # Three repeating characters
        analysis['issues'].append("Contains repeating characters")
    
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        analysis['issues'].append("Contains sequential characters")
    
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        analysis['issues'].append("Contains sequential numbers")
    
    return analysis

def generate_password(length = 12, use_uppercase = True, use_lowercase= True, use_digits = True, use_special = True):
    #character pool based on options
    characters = ""

    if use_uppercase:
        characters += string.ascii_uppercase
    
    if use_lowercase:
        characters += string.ascii_lowercase  # "abcdefghijklmnopqrstuvwxyz"
    
    if use_digits:
        characters += string.digits  # "0123456789"
    
    if use_special:
        characters += string.punctuation  # "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    
    #checking that we have atleast some characters
    if not characters:
        raise ValueError("Must include at least one character type")
    
    #generating password by randomaly selecting from character pool
    password = ""
    for _ in range(length):
        #secrets.choice() used cryptographically secure randomness
        password += secrets.choice(characters)

    return password, len(characters) #return both password and pool size

if __name__ == "__main__":

    if len(sys.argv)> 1 and sys.argv[1] == "--help":
        print("Usage: \n1)To generate a password: python passgen.py [--length {AnInteger}] [--no-special]")
        print("Examples:")
        print(" python passgen.py")
        print(" python passgen.py --length 16")
        print(" python passgen.py --length 8 --no-special")
        print("\nTo check strength of password: python passgen.py [--check {YourPassword}]")
        print("Example: python passgen.py --check 1@6%fh#k")
        sys.exit(0)

    if "--check" in sys.argv:
        #user wants to check an existing password
        index = sys.argv.index("--check")
        if index +1 < len(sys.argv):
            password_to_check = sys.argv[index+1]

            analysis = check_password_strength(password_to_check)
            crack_time = estimate_crack_time(analysis['entropy'])


            print(f"\n{'='*60}")
            print(f"Password Analysis")
            print(f"{'='*60}")
            print(f"Password length: {analysis['length']} characters")
            print(f"Strength: {analysis['strength']}")
            print(f"Entropy: {analysis['entropy']:.1f} bits")
            print(f"Estimated crack time: {crack_time}")
            
            if analysis['issues']:
                print(f"\nIssues:")
                for issue in analysis['issues']:
                    print(f"!!!! {issue}")
            else:
                print(f"\n!! Strong password !!")
            print()
        else:
            print("Error: --check requires a password argument")
            print("Usage: python3 passgen.py --check {'YourPassword123'}")
    
    else:
        # generate a password
        length = 12
        use_special = True

        #parse command line arguments and check for arguments
        if len(sys.argv)>1:

            #parse the custom length
            for i, arg in enumerate(sys.argv[1:]):
                if arg== "--length" and i+1 < len(sys.argv) - 1:
                        try:
                            length = int(sys.argv[i + 2])
                        except ValueError:
                            print("Error: Length must be an integer")
                            sys.exit(1)

                elif arg == "--no-special":
                    use_special = False
            
        #validate length
        if length <4:
            print("Error: password must be at least 4 characters")
            sys.exit(1)
            
        #generate password
        password , pool_size= generate_password(
            length = length,
            use_special = use_special
        )

        #analyze strength
        analysis = check_password_strength(password)

        #estimate crack time
        crack_time = estimate_crack_time(analysis['entropy'])

        #display results
        print(f"\n{'='*60}")
        print(f"Generated password: {password}")
        print(f"{'='*60}")
        print(f"Strength: {analysis['strength']}")
        print(f"Entropy: {analysis['entropy']:.2f} bits")
        print(f"Length: {analysis['length']} characters")
        print(f"Estimated crack time: {crack_time}")

        if analysis['issues']:
            print(f"\nIssues:")
            for issue in analysis['issues']:
                print(f" !!! {issue}")
        else:
            print(f"\n ~~ No issues found!")
        print()
    