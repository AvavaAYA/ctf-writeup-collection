import hashlib
import itertools


def brute_force_sha256(target_hash, fixed_part):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for item in itertools.product(chars, repeat=4):
        test_str = "".join(item) + fixed_part
        test_hash = hashlib.sha256(test_str.encode()).hexdigest()
        if test_hash == target_hash:
            return "".join(item)
    return None


def main():
    input_str = input(
        "Enter the challenge (format sha256(XXXX+fixed_string) == target_hash): "
    )
    fixed_part = input_str.split("+")[1].split(")")[0]
    target_hash = input_str.split("== ")[1]

    result = brute_force_sha256(target_hash, fixed_part)

    if result:
        print(f"Found XXXX: {result}")
    else:
        print("No matching XXXX found.")


if __name__ == "__main__":
    main()
