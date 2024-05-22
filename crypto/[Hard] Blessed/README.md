![](../../../../../assets/banner.png)

<img src='../../../../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Blessed</font>

13<sup>th</sup> May 2024 / Document No. D24.102.70

Prepared By: `7Rocky`

Challenge Author: `7Rocky`

Difficulty: <font color='orange'>Hard</font>

# Synopsis

Break an EC-LCG PRNG using lattice techniques in order to cheat a ZKP to be able to forge a BLS signature using rogue key attack.

## Description:

In their quest for materials and information, the crew finds themselves facing an unexpected challenge in a city governed by automated robots programmed to shoot non-registered residents on sight. Undeterred, they employ their hacking prowess to infiltrate the city's central control hub, where the robotic overlords oversee the administration of law and order.

## Skills Required (!)

- Python / SageMath
- Elliptic Curve
- LLL lattice reduction
- Modular arithmetic
- Pairing-based cryptography
- Zero-knowlegde proofs

## Skills Learned (!)

- BLS signatures
- BLS12-381 pairing-friendly elliptic curves
- EC-LCG
- Zero-knowledge proofs
- LLL lattice reduction

# Enumeration

We are given the Python source of the server that contains the flag.

## Analyzing the source code

The server defines an instance of `SuperComputer`, and we are allowed to interact with it using these commands:

```python
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
```

For that, we will need to create a robot, because we need a secret key to sign our commands:

```python
    def create(self) -> Dict[str, str]:
        r = Robot(next(self.rand))
        self.robots.append(r)
        return {'msg': 'Do not lose your secret key!', 'sk': hex(r._sk)[2:], **r.json()}
```

The previous method returns an instance of `Robot`:

```python
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
```

Observe that the robot ID is the output of this PRNG:

```python
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
```

Also, notice that the `SuperComputer` already has a total of 4 robots:

```python
    def __init__(self, n: int):
        self.rand:   Generator[int, None, None] = rng()
        self.robots: List[Robot]                = []

        for _ in range(n):
            self.create()
```

Because it is created as follows:

```python
    crew = {
        'Architects/Engineers',
        'Explosives Experts/Demolition Specialists',
        'Hackers',
        'Stealth/Infiltration specialists',
        'Scavengers',
    }

    sc = SuperComputer(len(crew - {'Hackers'}))  # No hackers here...
```

Once we have a robot, we can use the secret key to sign a command. For instance, we can run `list`:

```python
    def list(self, robot_id: int, sig: BLSSignature) -> Dict[str, str] | List[Dict[str, str]]:
        if not sig:
            return {'error': 'This command requires a signature'}

        r = self._find_robot_by_id(robot_id)

        if not r:
            return {'error': 'No robot found'}

        if not bls.Verify(r.pk, b'list', sig):
            return {'error': 'Invalid signature'}

        return [r.json() for r in self.robots]
```

This method will return the ID of all robots registered in the `SuperComputer`. This could be needed to crack the PRNG.

Moreover, we can run `join`:

```python
    def join(self, pk: BLSPubkey) -> Dict[str, str]:
        if not pk:
            return {'error': 'This command requires a public key'}

        r = Robot(next(self.rand), verified=False)
        r.pk = pk
        self.robots.append(r)
        return {'msg': 'Robot joined but not verified', 'robot_id': hex(r.robot_id)[2:]}
```

With this method we can add an existing robot to the `SuperComputer` using its public key. The difference with `create` is that the new robot is not verified, so we need to run `verify`:

```python
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
```

This method runs an interactive verification process to ensure that the public key of the robot is valid, but without disclosing the associated secret key. This is known as [zero-knowledge proof](https://en.wikipedia.org/wiki/Zero-knowledge_proof) (ZKP).

The target command we want to run to solve the challenge is `unveil_secrets`:

```python
    def unveil_secrets(self, agg_sig: BLSSignature) -> Dict[str, str]:
        agg_pk = [r.pk for r in self.robots if r.verified]

        if not agg_sig:
            return {'error': 'This command requires an aggregated signature'}
        elif bls.FastAggregateVerify(agg_pk, b'unveil_secrets', agg_sig):
            return {'msg': 'Secrets have been unveiled!', 'flag': FLAG}
        else:
            return {'error': 'Invalid aggregated signature'}
```

For this, we need a aggregated signature of all verified robots, which means that every robot must have signed this command. Otherwise, the verification will fail and we will not execute the command successfully.

## Finding the vulnerabilities

### BLS signatures

The server uses [BLS signatures](https://en.wikipedia.org/wiki/BLS_digital_signature), which involve pairing-based cryptography. The library [`py-ecc`](https://pypi.org/project/py-ecc/) makes a nice abstraction of what happens under the hood.

Basically, the BLS signature uses two elliptic curves $\mathbb{G}_1$ and $\mathbb{G}_2$ (known as BLS12-381), whose generator points are $G_1$ and $G_2$. These curves are pairing-friendly, which means that a pairing function can be defined here.

The idea is that two points of the elliptic curves can be associated to return another point of another elliptic curve, which is $\mathbb{G}_T$. Particularly, a pairing is a bilinear function:

$$
e: \mathbb{G}_1 \times \mathbb{G}_2 \to \mathbb{G}_T
$$

The bilinear property means that the following expressions hold for $P, R \in \mathbb{G}_1$ and $Q, S \in \mathbb{G}_2$:

$$
\begin{align*}
e(P + R, Q) = e(P, Q) + e(R, Q) \\
e(P, Q + S) = e(P, Q) + e(P, S)
\end{align*}
$$

As a result, for scalars $a$ and $b$, the following expressions also hold:

$$
\begin{align*}
e(a \cdot P, b \cdot Q) & = e(P, b \cdot Q)^a \\
                        & = e(a \cdot P, Q)^b \\
                        & = e(P, Q)^{ab} \\
                        & = e(b \cdot P, Q)^a \\
                        & = e(P, a \cdot Q)^b \\
                        & = e(b \cdot P, a \cdot Q) \\
                        & = e(ab \cdot P, Q) \\
                        & = e(P, ab \cdot Q)
\end{align*}
$$

This bilinear property allows to define the BLS signature scheme:

- A user takes a random integer $\mathrm{sk}$ and computes its public key as $\mathrm{Pk} = \mathrm{sk} \cdot G_1$.
- In order to sign a message $m$, the message must be hashed to a point (there are several methods to do this), so $H(m) \in \mathbb{G}_2$.
- The signature is $\sigma = \mathrm{sk} \cdot H(m) \in \mathbb{G}_2$

The verification process involves the pairing. The verifier only needs to compute $e(\mathrm{Pk}, H(m))$ and compare it to $e(G_1, \sigma)$. This works because:

$$
\begin{align*}
  e(\mathrm{Pk}, H(m)) & = e(\mathrm{sk} \cdot G_1, H(m)) \\
                       & = e(G_1, H(m))^{\mathrm{sk}} \\
                       & = e(G_1, \mathrm{sk} \cdot H(m)) \\
                       & = e(G_1, \sigma)
\end{align*}
$$

The relevance of BLS signatures comes with the fact that signatures can be aggregated. So, instead of verifying a message against several public keys, it suffices to verify only an aggregated signature against an aggregated public key:

$$
\begin{align*}
  \sigma_{\text{agg}} = \sigma_1 + \sigma_2 + \dots + \sigma_n \\
  \mathrm{Pk}_{\text{agg}} = \mathrm{Pk}_1 + \mathrm{Pk}_2 + \dots + \mathrm{Pk}_n \\ \\
  e(\mathrm{Pk}_{\text{agg}}, H(m)) \stackrel{?}{=} e(G_1, \sigma_{\text{agg}})
\end{align*}
$$

However, there is a problem with the aggregation if an attacker can use an arbitrary public key. The attacker is able to forge an aggregated signature for a given message, that is, tell that some victim user has signed a message:

- The attacker uses the following public key: $\mathrm{Pk}_\text{attacker} = \mathrm{sk}_\text{attacker} \cdot G_1 - \mathrm{Pk}_\text{victim}$
- The forged aggregated signature is: $\sigma_\text{forged} = \mathrm{sk}_\text{attacker} \cdot H(m)$
- The verifier will check that $e(\mathrm{Pk}_\text{victim} + \mathrm{Pk}_\text{attacker}, H(m))$ equals $e(G_1, \sigma_{\text{forged}})$

And it works because

$$
\begin{align*}
e(\mathrm{Pk}_\text{victim} + \mathrm{Pk}_\text{attacker}, H(m)) & = e(\mathrm{Pk}_\text{victim} + \mathrm{sk}_\text{attacker} \cdot G_1 - \mathrm{Pk}_\text{victim}, H(m)) \\
                                                                 & = e(\mathrm{sk}_\text{attacker} \cdot G_1, H(m)) \\
                                                                 & = e(G_1, H(m))^{\mathrm{sk}_\text{attacker}} \\
                                                                 & = e(G_1, \mathrm{sk}_\text{attacker} \cdot H(m)) \\
                                                                 & = e(G_1, \sigma_{\text{forged}})
\end{align*}
$$

This is known as rogue key attack. The way to prevent it is using a "Proof of Posession", which is to verify that the user that has a public key knows the associated secret key. Normally, the user should provide a signature of the public key, which proves that the user knows the secret key associated to the public key. Other methods might involve zero-knowledge proofs.

For more information about BLS12-381 curves and BLS signatures, refer to [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381) or [BLS Signatures & Withdrawals](https://medium.com/nethermind-eth/bls-signatures-withdrawals-bbf38658c242).

### Zero-knowledge proof

The way to prevent the rogue key attack in this challenge is using a zero-knowledge proof: We want the user to prove that they know $\mathrm{sk}$ such that $\mathrm{Pk} = \mathrm{sk} \cdot G_1$, but without disclosing $\mathrm{sk}$.

To achieve this, the server tells the user to pick a random integer $x$ and send $C = x \cdot \mathrm{Pk}$. Then, the server chooses randomly one of these two questions:

1. Show me $x$
2. Show me the result of $(\mathrm{sk} + x)$

If the question is 1., then the server can easily check that the given $x$ satisfies that $C = x \cdot \mathrm{Pk}$.

If the question is 2., then the server can check that the given value $(\mathrm{sk} + x$) satisfies that $\mathrm{Pk} + C = (\mathrm{sk} + x) \cdot G_1$.

If this experiment is repeated several times and the user is not able to predict the question, then it is practically impossible to lie on the ZKP:

```python
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
```

If the attacker is able to predict the question, then the attacker is able to cheat the ZKP (that is, show that they know $\mathrm{sk}$ such that $\mathrm{Pk}_\text{attacker} = \mathrm{sk} \cdot G_1$, when it is false):

- For question 1., the attacker simply sends the value of $x$ such that $C = x \cdot \mathrm{Pk}_\text{attacker}$.
- But for question 2., they can compute a special $C = \mathrm{sk}_x \cdot G_1 - \mathrm{Pk}_\text{attacker}$, send it, and then use $\mathrm{sk}_x$ as $(\mathrm{sk} + x)$. The server will check that $\mathrm{Pk}_\text{attacker} + C = \mathrm{sk}_x \cdot G_1$, which is true because

$$
\mathrm{Pk}_\text{attacker} + C = \mathrm{Pk}_\text{attacker} + \mathrm{sk}_x \cdot G_1 - \mathrm{Pk}_\text{attacker} = \mathrm{sk}_x \cdot G_1
$$

### EC-LCG

The server uses this PRNG instance to choose the question for the ZKP. So, we will need to crack the PRNG to predict questions and thus cheat the ZKP:

```python
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
```

This algorithm is an EC-LCG that uses curve [P256](https://neuromancer.sk/std/nist/P-256), denoted by $E(\mathbb{F}_p)$, in the following way:

$$
\begin{cases}
  W_0 & = \mathrm{seed} \cdot G + B \\
  W_n & = W_{n - 1} + G \\
  r_{2 n - 1} & = (W_n)_\mathrm{x} \gg 32 \\
  r_{2 n} & = (W_n)_\mathrm{y} \gg 32 \\
\end{cases}
$$

Where $B, G \in E(\mathbb{F}_p)$, $\mathrm{seed} \in \mathbb{Z}$ and $n > 0$. The outputs of the PRNG are $r_i$:

$$
\begin{cases}
  r_1 & = (W_1)_\mathrm{x} \gg 32 \\
  r_2 & = (W_1)_\mathrm{y} \gg 32 \\
  r_3 & = (W_2)_\mathrm{x} \gg 32 \\
  r_4 & = (W_2)_\mathrm{y} \gg 32 \\
  \dots
\end{cases}
$$

The same can be expressed as follows:

$$
\begin{cases}
  W_n & = (\mathrm{seed} + n) \cdot G + B \\
  r_{2 n - 1} & = (W_n)_\mathrm{x} \gg 32 \\
  r_{2 n} & = (W_n)_\mathrm{y} \gg 32 \\
\end{cases}
$$

The key to break this EC-LCG implementation is that $W_{n + 1} - W_n = G$. However, we are not given the exact values of $(W_n)_\text{x}$ and $(W_n)_\text{y}$, so we cannot simply find a point $W_n$ to crack the EC-LCG. Instead, we can write some equations with the information we know.

Let's use the following notation for the known outputs:

$$
u_n = r_{2n - 1} = (W_n)_\mathrm{x} \gg 32 \qquad v_n = r_{2n} = (W_n)_\mathrm{y}\gg 32
$$

And these for the unknowns:

$$
a_n = W_n - \big((W_n)_\mathrm{x} \gg 32\big) \ll 32 \qquad b_n = W_n - \big((W_n)_\mathrm{y} \gg 32\big) \ll 32
$$

We know the curve parameters and the generator point $G$ ([P256](https://neuromancer.sk/std/nist/P-256)). We know that $(u_n + a_n, v_n + b_n) \in E(\mathbb{F}_p)$, so:

$$
(v_n + b_n)^2 = (u_n + a_n)^3 + a \cdot (u_n + a_n) + b \mod{p}
$$

Moreover, we know that

$$
G = W_{n + 1} - W_n = (u_{n + 1} + a_{n + 1}, v_{n + 1} + b_{n + 1}) - (u_n + a_n, v_n + b_n)
$$

This can be expressed using point addition formulas:

$$
\begin{cases}
  (x_1, y_1) + (x_2, y_2) = (x_3, y_3) \\ \\
  \lambda = (y_2 - y_1) \cdot (x_2 - x_1)^{-1} \mod{p} \\
  x_3 = \lambda^2 - x_1 - x_2 \\
  y_3 = \lambda \cdot (x_1 - x_3) - y_1
\end{cases}
$$

We can get rid of $\lambda$ in the formula for $x_3$:

$$
\begin{align*}
  x_3 & = \lambda^2 - x_1 - x_2 \iff \\
  x_3 & = \big((y_2 - y_1) \cdot (x_2 - x_1)^{-1}\big)^2 - x_1 - x_2 \iff \\
  x_3 & = (y_2 - y_1)^2 \cdot (x_2 - x_1)^{-2} - x_1 - x_2 \iff \\
  0 & = x_3 - (y_2 - y_1)^2 \cdot (x_2 - x_1)^{-2} + x_1 + x_2 \iff \\
  0 & = x_3 \cdot (x_2 - x_1)^2 - (y_2 - y_1)^2 + (x_1 + x_2) \cdot (x_2 - x_1)^2 \\
  0 & = (x_1 + x_2 + x_3) \cdot (x_2 - x_1)^2 - (y_2 - y_1)^2
\end{align*}
$$

And the same with the formula for $y_3$:

$$
\begin{align*}
  y_3 & = \lambda \cdot (x_1 - x_3) - y_1 \iff \\
  y_3 & = \big((y_2 - y_1) \cdot (x_2 - x_1)^{-1}\big) \cdot (x_1 - x_3) - y_1 \iff \\
  0 & = y_3 - \big((y_2 - y_1) \cdot (x_2 - x_1)^{-1}\big) \cdot (x_1 - x_3) + y_1 \iff \\
  0 & = y_3 - (y_2 - y_1) \cdot (x_2 - x_1)^{-1} \cdot (x_1 - x_3) + y_1 \iff \\
  0 & = y_3 \cdot (x_2 - x_1) - (y_2 - y_1) \cdot (x_1 - x_3) + y_1 \cdot (x_2 - x_1) \iff \\
  0 & = (y_3 + y_1) \cdot (x_2 - x_1) - (y_2 - y_1) \cdot (x_1 - x_3)
\end{align*}
$$

Given the fact that we have more unknowns than equations, but the linear unknowns are bounded to $2^{32}$, we can use a lattice to solve a Shortest Vector Problem using LLL.

We will use a total of 6 PRNG outputs ($u_1$, $v_1$, $u_2$, $v_2$, $u_3$, and $v_3$), that is, 3 points ($W_1$, $W_2$ and $W_3$), and we can get 7 independent equations:

$$
\begin{cases}
  W_1 \in E(\mathbb{F}_p) \\
  W_2 \in E(\mathbb{F}_p) \\
  W_3 \in E(\mathbb{F}_p) \\
  \\
  W_2 - W_1 = G \quad \text{(for x and y)} \\
  W_3 - W_2 = G \quad \text{(for x and y)}
\end{cases}
$$

$$
\begin{cases}
  (u_1 + a_1)^3 + a \cdot (u_1 + a_1) + b - (v_1 + b_1)^2 = 0 \mod{p} \\
  (u_2 + a_2)^3 + a \cdot (u_2 + a_2) + b - (v_2 + b_2)^2 = 0 \mod{p} \\
  (u_3 + a_3)^3 + a \cdot (u_3 + a_3) + b - (v_3 + b_3)^2 = 0 \mod{p} \\
  \\
  ((u_1 + a_1) + (u_2 + a_2) + G_\mathrm{x}) \cdot ((u_2 + a_2) - (u_1 + a_1))^2 - ((v_2 + b_2) \textcolor{red}{+} (v_1 + b_1))^2 = 0 \mod{p} \\
  ((u_2 + a_2) + (u_3 + a_3) + G_\mathrm{x}) \cdot ((u_3 + a_3) - (u_2 + a_2))^2 - ((v_3 + b_3) \textcolor{red}{+} (v_2 + b_2))^2 = 0 \mod{p} \\
  \\
  (G_\mathrm{y} \textcolor{red}{-} (v_1 + b_1)) \cdot ((u_2 + a_2) - (u_1 + a_1)) - ((v_2 + b_2) \textcolor{red}{+} (v_1 + b_1)) \cdot ((u_1 + a_1) - G_\mathrm{x}) = 0 \mod{p} \\
  (G_\mathrm{y} \textcolor{red}{-} (v_2 + b_2)) \cdot ((u_3 + a_3) - (u_2 + a_2)) - ((v_3 + b_3) \textcolor{red}{+} (v_2 + b_2)) \cdot ((u_2 + a_2) - G_\mathrm{x}) = 0 \mod{p}
\end{cases}
$$

The signs colored in red are to indicate that we are expressing $W_{n + 1} - W_n = G$, to indicate that $-W_n = (u_n + a_n, -v_n - b_n)$.

We can get rid of $\mod{p}$ by adding some integers $k_1, \dots, k_7$ multiplied by $p$:

$$
\begin{cases}
  (u_1 + a_1)^3 + a \cdot (u_1 + a_1) + b - (v_1 + b_1)^2 + k_1 \cdot p = 0 \\
  (u_2 + a_2)^3 + a \cdot (u_2 + a_2) + b - (v_2 + b_2)^2 + k_2 \cdot p = 0 \\
  (u_3 + a_3)^3 + a \cdot (u_3 + a_3) + b - (v_3 + b_3)^2 + k_3 \cdot p = 0 \\
  \\
  ((u_1 + a_1) + (u_2 + a_2) + G_\mathrm{x}) \cdot ((u_2 + a_2) - (u_1 + a_1))^2 - ((v_2 + b_2) \textcolor{red}{+} (v_1 + b_1))^2 + k_4 \cdot p = 0 \\
  ((u_2 + a_2) + (u_3 + a_3) + G_\mathrm{x}) \cdot ((u_3 + a_3) - (u_2 + a_2))^2 - ((v_3 + b_3) \textcolor{red}{+} (v_2 + b_2))^2 + k_5 \cdot p = 0 \\
  \\
  (G_\mathrm{y} \textcolor{red}{-} (v_1 + b_1)) \cdot ((u_2 + a_2) - (u_1 + a_1)) - ((v_2 + b_2) \textcolor{red}{+} (v_1 + b_1)) \cdot ((u_1 + a_1) - G_\mathrm{x}) + k_6 \cdot p = 0 \\
  (G_\mathrm{y} \textcolor{red}{-} (v_2 + b_2)) \cdot ((u_3 + a_3) - (u_2 + a_2)) - ((v_3 + b_3) \textcolor{red}{+} (v_2 + b_2)) \cdot ((u_2 + a_2) - G_\mathrm{x}) + k_7 \cdot p = 0
\end{cases}
$$

Obviously, we don't have only 6 unknowns, because there are interactions between variables (i.e. $a_1 \cdot a_2$ or $a_1^3$). However, these variables are also bounded and short when compared to $p$. As a result, we can use a lattice basis like this to determine the value of $a_1$, $b_1$, $a_2$, $b_2$, $a_3$, and $b_3$:

$$
\begin{bmatrix}
  \begin{pmatrix} p & & & \\ & p & & \\ & & \ddots & \\ & & & p \end{pmatrix} & {\begin{pmatrix}
    \mathrm{eq_1} & & \mathrm{coefficients} \\
    \mathrm{eq_2} & & \mathrm{coefficients} \\
    & \dots & \\
    \mathrm{eq_7} & & \mathrm{coefficients}
  \end{pmatrix}} \\ \\
  & \begin{pmatrix} 1 & & & & \\ & 1 & & & \\ & & \ddots & \\ & & & 1 & \\ & & & & 2^{256}\end{pmatrix} 
\end{bmatrix}
$$

And the target vector is $(k_1, \dots, k_7,\dots, a_1, b_1, a_2, b_2, a_3, b_3, 2^{256})$, which is possible to get using LLL on the lattice basis matrix.

Once having $a_1$, $b_1$, $a_2$, $b_2$, $a_3$, and $b_3$, we can find $W_1$, $W_2$ and $W_3$ to crack the PRNG.

# Solution

So, this is the strategy to solve the challenge:

- We must run `unveil_secret`, which needs an aggregated signature of all verified robots
- We can use a rogue key attack to forge the signature
- For this, we must provide a malicious public key, so we will be running `join`
- We need to verify the robot, that is, we need to prove that we have the secret key associated to the malicious public key
- It is not easy to find a secret key that can generate the malicious public key, so we need to cheat in order to complete the zero-knowledge proof
- For this, we need to know exactly what question is the server going to ask, so we need to crack the EC-LCG PRNG
- We need 6 outputs, so we can create a new robot (5$^\text{th}$ output), use it to list existing robots, and then join another robot with the malicious public key (6$^\text{th}$ output)

## Exploitation

The interaction with the server is using JSON (except for the verification process), so we can use this function to send and receive JSON data:

```python
def sr(data):
    io.sendlineafter(b'> ', json.dumps(data).encode())
    return json.loads(io.recvline().decode())
```

First, we create a robot and use it to list the rest:

```python
res = sr({'cmd': 'create'})
sk = int(res.get('sk'), 16)
robot_id = int(res.get('robot_id'), 16)

cmd = 'list'
sig = bls.Sign(sk, cmd.encode())
res = sr({'cmd': cmd, 'robot_id': hex(robot_id), 'sig': sig.hex()})

ids, Pks = [], []

for r in res:
    ids.append(int(r.get('robot_id'), 16))
    Pks.append(decompress_G1(G1Compressed(int(r.get('pk'), 16))))
```

With the public keys, we can craft the malicious public key for the rogue key attack ([`py-ecc`](https://pypi.org/project/py-ecc/) makes it very easy to implement):

```python
sk = 1337
cmd = 'unveil_secrets'
pk = bls.SkToPk(sk)
sig = bls.Sign(sk, cmd.encode())
Pk = pubkey_to_G1(pk)

Pk_prime = add(Pk, neg(reduce(add, Pks, Z1)))
pk_prime = G1_to_pubkey(Pk_prime)
assert normalize(add(reduce(add, Pks), Pk_prime)) == normalize(Pk)
io.success('Forged signature!')
```

Now, we join this malicious public key and get the 6$^\mathrm{th}$ PRNG output:

```python
res = sr({'cmd': 'join', 'pk': pk_prime.hex()})
robot_id = int(res.get('robot_id'), 16)
ids.append(robot_id)
assert len(ids) == 6
```

Then, we crack the EC-LCG PRNG:

```python
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)


def crack_ec_lcg(values):
    assert len(values) == 6
    u1, v1, u2, v2, u3, v3 = values
    a1, b1, a2, b2, a3, b3 = PolynomialRing(K, 'a1, b1, a2, b2, a3, b3').gens()

    ec1 = (v1 + b1) ** 2 - (u1 + a1) ** 3 - a * (u1 + a1) - b
    ec2 = (v2 + b2) ** 2 - (u2 + a2) ** 3 - a * (u2 + a2) - b
    ec3 = (v3 + b3) ** 2 - (u3 + a3) ** 3 - a * (u3 + a3) - b

    ec4 = ((u1 + a1) + (u2 + a2) + G.x()) * ((u2 + a2) - (u1 + a1)) ** 2 - ((v2 + b2) + (v1 + b1)) ** 2
    ec5 = ((u2 + a2) + (u3 + a3) + G.x()) * ((u3 + a3) - (u2 + a2)) ** 2 - ((v3 + b3) + (v2 + b2)) ** 2
    ec6 = (G.y() - (v1 + b1)) * ((u2 + a2) - (u1 + a1)) - ((v2 + b2) + (v1 + b1)) * ((u1 + a1) - G.x())
    ec7 = (G.y() - (v2 + b2)) * ((u3 + a3) - (u2 + a2)) - ((v3 + b3) + (v2 + b2)) * ((u2 + a2) - G.x())

    A, v = Sequence([ec1, ec2, ec3, ec4, ec5, ec6, ec7]).coefficients_monomials(sparse=False)
    A = A.change_ring(ZZ)

    A = (identity_matrix(7) * p).augment(A)
    A = A.stack(zero_matrix(len(v), 7).augment(identity_matrix(len(v))))
    A[-1, -1] = 2 ** 256

    L = A.T.LLL()
    assert L[-1][-1] == 2 ** 256
    a1, b1, a2, b2, a3, b3 = L[-1][-7:-1]

    W1 = E(u1 + a1, v1 + b1)
    W2 = E(u2 + a2, v2 + b2)
    W3 = E(u3 + a3, v3 + b3)
    return W3
```

With this, we can cheat the ZKP to verify the malicious public key:

```python
Wn = crack_ec_lcg([i << 32 for i in ids])
io.success('Cracked EC-LCG!')

prog = io.progress('Cheating ZKP')
sr({'cmd': 'verify', 'robot_id': hex(robot_id)})

for _ in range(64 // 2):
    Wn += G

    for c in Wn.xy():
        if (int(c) >> 32) & 1:
            x = 1337
            C = multiply(Pk_prime, x)
            assert normalize(multiply(Pk_prime, x)) == normalize(C)
            io.sendlineafter(b'Take a random value x and send me C = x * pk (hex): ', bytes(G1_to_pubkey(C)).hex().encode())
            io.sendlineafter(b'Give me x (hex): ', hex(x).encode())
        else:
            sk_x = 1337
            C = add(multiply(G1, sk_x), neg(Pk_prime))
            assert normalize(add(multiply(G1, sk_x), neg(Pk_prime))) == normalize(C) 
            io.sendlineafter(b'Take a random value x and send me C = x * pk (hex): ', bytes(G1_to_pubkey(C)).hex().encode())
            io.sendlineafter(b'Give me (sk + x) (hex): ', hex(sk_x).encode())

prog.success()
```

Finally, we run the `unveil_secrets` command, with the malicious aggregated signature:

```python
res = sr({'cmd': cmd, 'sig': sig.hex()})
sr({'cmd': 'exit'})
io.success(res.get('flag'))
```

### Getting the flag

If we run the script, we will solve the challenge and get the flag:

```console
$ python3 solve.py 
[+] Starting local process '/usr/bin/python3': pid 342
[+] Forged signature!
[+] Cracked EC-LCG!
[+] Cheating ZKP: Done
[+] HTB{uNv31leD_5eCre7s_0f_BLS_r0gu3_k3y_4t7aCk_w1th_cu5t0m_zkp_4nd_ec-lcg!!}
[*] Stopped process '/usr/bin/python3' (pid 342)
```
