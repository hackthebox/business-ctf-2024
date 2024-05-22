import json

from eth_typing import BLSPrivateKey, BLSPubkey, BLSSignature
from secrets import randbelow
from typing import Dict, Generator, List

from Crypto.PublicKey import ECC

from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import pubkey_to_G1
from py_ecc.bls.point_compression import decompress_G1
from py_ecc.bls.typing import G1Compressed

from py_ecc.optimized_bls12_381.optimized_curve import add, curve_order, G1, multiply, neg, normalize


try:
    with open('flag.txt') as f:
        FLAG = f.read().strip()
except FileNotFoundError:
    FLAG = 'HTB{f4k3_fl4g_f0r_t3st1ng}'


def rng() -> Generator[int, None, None]:
    seed = randbelow(curve_order)
    Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    G = ECC.EccPoint(Gx, Gy, curve='p256')
    B = ECC.generate(curve='p256').pointQ
    W0 = G * seed + B
    Wn = W0

    while True:
        Wn += G
        yield Wn.x >> 32
        yield Wn.y >> 32


class Robot:
    def __init__(self, robot_id: int, verified: bool = True):
        self.robot_id: int           = robot_id
        self.verified: bool          = verified
        self.pk:       BLSPubkey     = BLSPubkey(b'')
        self._sk:      BLSPrivateKey = BLSPrivateKey(0)

        if self.verified:
            self._sk = BLSPrivateKey(randbelow(curve_order))
            self.pk = bls.SkToPk(self._sk)

    def json(self) -> Dict[str, str]:
        return {'robot_id': hex(self.robot_id)[2:], 'pk': self.pk.hex()}


class SuperComputer:
    def __init__(self, n: int):
        self.rand:   Generator[int, None, None] = rng()
        self.robots: List[Robot]                = []

        for _ in range(n):
            self.create()

    def _find_robot_by_id(self, robot_id: int) -> Robot | None:
        for r in self.robots:
            if r.robot_id == robot_id:
                return r

    def create(self) -> Dict[str, str]:
        r = Robot(next(self.rand))
        self.robots.append(r)
        return {'msg': 'Do not lose your secret key!', 'sk': hex(r._sk)[2:], **r.json()}

    def join(self, pk: BLSPubkey) -> Dict[str, str]:
        if not pk:
            return {'error': 'This command requires a public key'}

        r = Robot(next(self.rand), verified=False)
        r.pk = pk
        self.robots.append(r)
        return {'msg': 'Robot joined but not verified', 'robot_id': hex(r.robot_id)[2:]}

    def verify(self, robot_id: int) -> Dict[str, str]:
        r = self._find_robot_by_id(robot_id)

        if not r:
            return {'error': 'No robot found'}

        if r.verified:
            return {'error': 'User already verified'}

        print(json.dumps({'msg': 'Prove that you have the secret key that corresponds to your public key: pk = sk * G1'}))

        Pk = pubkey_to_G1(r.pk)

        for _ in range(64):
            C_hex = input('Take a random value x and send me C = x * pk (hex): ')
            C = decompress_G1(G1Compressed(int(C_hex, 16)))

            if next(self.rand) & 1:
                x = int(input('Give me x (hex): '), 16)

                if normalize(multiply(Pk, x)) != normalize(C):
                    return {'error': 'Proof failed!'}
            else:
                sk_x = int(input('Give me (sk + x) (hex): '), 16)

                if normalize(add(multiply(G1, sk_x), neg(Pk))) != normalize(C):
                    return {'error': 'Proof failed!'}

        r.verified = True
        return {'msg': 'Robot verified'}

    def list(self, robot_id: int, sig: BLSSignature) -> Dict[str, str] | List[Dict[str, str]]:
        if not sig:
            return {'error': 'This command requires a signature'}

        r = self._find_robot_by_id(robot_id)

        if not r:
            return {'error': 'No robot found'}

        if not bls.Verify(r.pk, b'list', sig):
            return {'error': 'Invalid signature'}

        return [r.json() for r in self.robots]

    def unveil_secrets(self, agg_sig: BLSSignature) -> Dict[str, str]:
        agg_pk = [r.pk for r in self.robots if r.verified]

        if not agg_sig:
            return {'error': 'This command requires an aggregated signature'}
        elif bls.FastAggregateVerify(agg_pk, b'unveil_secrets', agg_sig):
            return {'msg': 'Secrets have been unveiled!', 'flag': FLAG}
        else:
            return {'error': 'Invalid aggregated signature'}

    def help(self) -> Dict[str, str]:
        return {
            'help':           'Show this panel',
            'create':         'Generate a new robot, already verified',
            'join':           'Add a new robot, given a public key and a signature',
            'verify':         'Start interactive process to verify a robot given an ID',
            'list':           'Return a list of all existing robots',
            'unveil_secrets': 'Show the secrets given an aggregated signature of all registered robots',
            'exit':           'Shutdown the SuperComputer',
        }

    def run_cmd(self, data: Dict[str, str]) -> Dict[str, str] | List[Dict[str, str]]:
        cmd      = data.get('cmd')
        pk       = BLSPubkey(bytes.fromhex(data.get('pk', '')))
        sig      = BLSSignature(bytes.fromhex(data.get('sig', '')))
        robot_id = int(data.get('robot_id', '0'), 16)

        if cmd == 'create':
            return self.create()
        elif cmd == 'join':
            return self.join(pk)
        elif cmd == 'verify':
            return self.verify(robot_id)
        elif cmd == 'list':
            return self.list(robot_id, sig)
        elif cmd == 'unveil_secrets':
            return self.unveil_secrets(sig)
        elif cmd == 'exit':
            return {'error': 'exit'}

        return self.help()


def main():
    print('Welcome! You have been invited to use our SuperComputer, which is very powerful and totally secure. Only sophisticated robots are able to use it, so you need to create a robot to interact with the SuperComputer or maybe join an existing one. The key to our success is that critical operations need the approval of all registered robots. Hackers cannot beat our security!\n')

    crew = {
        'Architects/Engineers',
        'Explosives Experts/Demolition Specialists',
        'Hackers',
        'Stealth/Infiltration specialists',
        'Scavengers',
    }

    sc = SuperComputer(len(crew - {'Hackers'}))  # No hackers here...
    print(json.dumps(sc.help(), indent=2), end='\n\n')

    while True:
        res = sc.run_cmd(json.loads(input('> ')))
        print(json.dumps(res), end='\n\n')

        if 'error' in res:
            break


if __name__ == '__main__':
    main()
