import sys

def cesar_cipher(text: str, shift: int) -> str:
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(char)
    return "".join(result)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 cesar.py \"<texto>\" <corrimiento>")
        sys.exit(1)
   
    text = sys.argv[1]
    shift = int(sys.argv[2])
    print(cesar_cipher(text, shift))
