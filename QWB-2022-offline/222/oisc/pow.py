def proof_of_work_okay(chall, solution, hardness):
    h = hashlib.sha256(chall.encode('ASCII') +
                       struct.pack('<Q', solution)).hexdigest()
    return int(h, 16) < 2**256 / hardness


def check_pow():
    challenge = random_string()
    print('Proof of work challenge: {}_{}'.format(4096, challenge))
    sys.stdout.write('Your response? ')
    sys.stdout.flush()
    sol = int(input())
    if not proof_of_work_okay(challenge, sol, 4096):
        print('Wrong :(')
        exit(1)
