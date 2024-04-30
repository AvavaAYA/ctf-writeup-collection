# MRCTF Crypto部分
[toc]

## RSA known d???
[[1] Ellen Jochemsz and Alexander May. A Strategy for Finding Roots of Multivariate
Polynomials with New Applications
in Attacking RSA Variants](https://link.springer.com/chapter/10.1007/11935230_18)

[[2] Santanu Sarkar and Subhamoy Maitra. Some Applications of Lattice Based Root Finding Techniques](https://eprint.iacr.org/2010/146)

[Implementation from github](https://github.com/elliptic-shiho/crypto_misc/blob/master/small_root/jochemsz_may.sage)

### 出题idea

给出的是$A = \mu d - z$
$k$也给了
所以可以计算出$d$的高位，然后$\mu$的高位也有了
然后就求解方程$A - (d_0 + x) * (u_1 + y) + z$的小根即可
但用的并不完全是Coppersmith's method而是[1]中的Extended Strategy

具体参数在两个论文里找吧，这里就不写了

CNSS 的wp并没有收到

AAA 队伍直接用的多元coppersmith的板子，跑了两个小时... 反正出了

```python
P.<u, d, z> = PolynomialRing(Zmod(A))
f = (u1 + u) * (d0 + d) - z
bounds = (1 << 160, 1 << 513, 1 << 226)
small_roots(f, bounds, m=4, d=5)
```

r4kapig 队伍是将方程乘了$e$倍，消去$d$，转成了用$N, p+q$表示，个人感觉没什么必要，bound都是$\sqrt{N}$。当然这么解肯定也是没问题的。

### exp

```python
from sage.all import *
import itertools
from time import time
from Crypto.Util.number import long_to_bytes


# display matrix picture with 0 and X
# references: https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage
def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%03d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print (a)

def sort_monomials(monomials):
    # 直接用 sorted() 方法也是可以的
    x, y, z = monomials[0].parent().gens()
    Mx = []
    My = []
    Mz = []
    degx = max([monomial.degree(x) for monomial in monomials])
    degy = max([monomial.degree(y) for monomial in monomials])
    degz = max([monomial.degree(z) for monomial in monomials])
    for i in range(degx + 1):
        for j in range(degy + 1):
            for k in range(degz + 1):
                if k+j > i:
                    break
                mono = x^i * y^j * z^k
                if mono in monomials:
                    Mx += [mono]
    for j in range(degy + 1):
        for k in range(degz + 1):
            for i in range(degx + 1):
                if k > j:
                    break
                mono = x^i * y^j * z^k
                if mono in monomials and mono not in Mx:
                    My += [mono]
    for k in range(degz + 1):
        for j in range(degy + 1):
            for i in range(degx + 1):
                mono = x^i * y^j * z^k
                if mono in monomials and mono not in (Mx+My):
                    Mz += [mono]
    return Mx + My + Mz


def jochemsz_may_trivariate(pol, XX, YY, ZZ, WW, tau, mm):
    '''
    Implementation of Finding roots of trivariate polynomial [1].
    Thanks @Bono_iPad
    References: 
        [1] Ellen Jochemsz and Alexander May. "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants"
    '''
    tt = floor(mm * tau)
    cond = XX^(7 + 9*tau + 3*tau^2) * (YY*ZZ)^(5+9/2*tau) < WW^(3 + 3*tau)
    print ('[+] Bound check: X^{7+9tau+3tau^2} * (YZ)^{5+9/2tau} < W^{3+3tau}:', )
    if cond:
        print( 'OK')
    else:
        print ('NG')

    # Polynomial constant coefficient (a_0) must be 1
    # XXX: can a_0 be zero?
    f_ = pol
    a0 = f_.constant_coefficient()

    while gcd(a0, XX) != 1:
        XX += 1
    while gcd(a0, YY) != 1:
        YY += 1
    while gcd(a0, ZZ) != 1:
        ZZ += 1
    while gcd(a0, WW) != 1:
        WW += 1

    RR = WW * XX^(2*(mm-1)+tt) * (YY*ZZ)^(mm-1)

    if a0 != 0:
        F = Zmod(RR)
        PK = PolynomialRing(F, 'xs, ys, zs')
        f_ = PR(PK(f_) * F(a0)^-1)

    # Construct set `S` (cf.[1] p.8)
    S = set()
    for i2, i3 in itertools.product(range(0, mm), repeat=2):
        for i1 in range(0, 2*(mm-1) - (i2 + i3) + tt + 1):
            S.add(x^i1 * y^i2 * z^i3)
    m_S = []
    for k in range(mm):
        for j in range(mm):
            for i in range(2*(mm-1) - (i2 + i3) + tt + 1):
                m_S += [x^i*y^j*z^k]
    S = m_S

    # Construct set `M` (cf.[1] p.8)
    M = set()
    for i2, i3 in itertools.product(range(0, mm + 1), repeat=2):
        for i1 in range(0, 2*mm - (i2 + i3) + tt + 1):
            M.add(x^i1 * y^i2 * z^i3)
    M_S = list(M - set(S))

    m_M_S = []
    deg_x = max([mono.degree(x) for mono in M_S])
    deg_y = max([mono.degree(y) for mono in M_S])
    deg_z = max([mono.degree(z) for mono in M_S])
    for k in range(deg_z + 1):
        for j in range(deg_y + 1):
            for i in range(deg_x + 1):
                mono = x^i*y^j*z^k
                if mono in M_S:
                    m_M_S += [mono]
    M_S = m_M_S

    # Construct polynomial `g`, `g'` for basis of lattice
    g = []
    g_ = []
    M_S = sort_monomials(M_S)
    S = sort_monomials(S)
    for monomial in S:
        i1 = monomial.degree(x)
        i2 = monomial.degree(y)
        i3 = monomial.degree(z)
        g += [monomial * f_ * XX^(2*(mm-1)+tt-i1) * YY^(mm-1-i2) * ZZ^(mm-1-i3)]

    for monomial in M_S:
        g_ += [monomial * RR]

    # Construct Lattice from `g`, `g'`
    monomials_G = []
    monomials = []
    G = g + g_
    deg_x = deg_y = deg_z = 0
    for g_poly in G:
        monomials_G += g_poly.monomials()
        deg_x = max(deg_x, g_poly.degree(x))
        deg_y = max(deg_y, g_poly.degree(y))
        deg_z = max(deg_z, g_poly.degree(z))
    monomials_G = sorted(set(monomials_G))

    for k in range(deg_z + 1):
        for j in range(deg_y + 1):
            for i in range(deg_x + 1):
                mono = x^i*y^j*z^k
                if mono in monomials_G:
                    monomials += [x^i*y^j*z^k]
    assert len(monomials) == len(G)
    monomials = sort_monomials(monomials)
    dims = len(monomials)
    M = Matrix(IntegerRing(), dims)
    for i in range(dims):
        M[i, 0] = G[i](0, 0, 0)
        for j in range(dims):
            if monomials[j] in G[i].monomials():
                M[i, j] = G[i].monomial_coefficient(monomials[j]) * monomials[j](XX, YY, ZZ)
    matrix_overview(M)
    print ()
    print ('=' * 128)
    print ()

    # LLL

    start = time()
    B = M.LLL()
    matrix_overview(B)
    print('[+] LLL cost %d sec' % (time() - start))

    # Re-construct polynomial `H_i` from Reduced-lattice
    H = [(i, 0) for i in range(dims)]
    H = dict(H)
    for i in range(dims):
        for j in range(dims):
            H[i] += PR((monomials[j] * B[i, j]) / monomials[j](XX, YY, ZZ))

    PX = PolynomialRing(IntegerRing(), 'xn')
    xn = PX.gen()
    PY = PolynomialRing(IntegerRing(), 'yn')
    yn = PX.gen()
    PZ = PolynomialRing(IntegerRing(), 'zn')
    zn = PX.gen()

    # Solve for `x`
    r1 = H[2].resultant(pol, y)
    r2 = H[3].resultant(pol, y)
    r3 = r1.resultant(r2, z)
    x_roots = map(lambda t: t[0], r3.subs(x=xn).roots())
    x_roots = list(x_roots)
    assert len(x_roots) > 0
    if len(x_roots) == 1 and x_roots[0] == 0:
        print ('[-] Can\'t find non-trivial solution for `x`')
        return 0, 0, 0
    x_root = x_roots[0]
    print ('[+] Found x0 = %d' % x_root)

    # Solve for `z`
    r1_ = r1.subs(x=x_root)
    r2_ = r2.subs(x=x_root)
    z_roots = map(lambda t: t[0], gcd(r1_, r2_).subs(z=zn).roots())
    z_roots = list(z_roots)
    assert len(z_roots) > 0
    if len(z_roots) == 1 and z_roots[0] == 0:
        print ('[-] Can\'t find non-trivial solution for `z`')
        return 0, 0, 0
    z_root = z_roots[0]
    print ('[+] Found z0 = %d' % z_root)

    # Solve for `y`
    y_roots = map(lambda t: t[0], H[2].subs(x=x_root, z=z_root).subs(y=yn).roots())
    y_roots = list(y_roots)
    assert len(y_roots) > 0
    if len(y_roots) == 1 and y_roots[0] == 0:
        print ('[-] Can\'t find non-trivial solution for `y`')
        return 0, 0, 0
    y_root = y_roots[0]
    print ('[+] Found y0 = %d' % y_root)
    assert pol(x_root, y_root, z_root) == 0
    return (x_root, y_root, z_root)


if __name__ == '__main__':
    N = 117414633671752050138386682330739643195299492683664841432052832647006837465319914976570632498827904024361936361316279151369869674766255600494477132420900578358372154114980027200764003785179394323791637118873183718151669596835230859541488350138359034623741460701911235393088738659088029964817850063004699481393
    e = 65537
    c = 115843124930761541844112149745896665055407652312785851954446056382349196266514659620373632621041716901633129915836971325724532478319133843217910775349226685806695177782362744570208526725829461967445231711156767681227931194403259045395250229129610249187251587110482667776835009746020707905596336294238188501238
    A = 4849254489119593945086760660950184189790673953794694114912728871022741293555577578157385296140287281027577275547677699366237305159247461639563009572060872438499072586452505629029761648221357324159409792540579148995423472780520896461679304910471546297464375789584369354690941522653749872459652710049389270991331235188622397016412252760716201752517972377858438047494059295988880794315506538932218993358340505605859649205715921011975299642390630914314462795547814196473172896215345804733107162805832247626015036
    k = 17397

    d0 = (1 + k * N) // e
    u1 = A // d0

    alpha = 0.65
    beta = 0.22

    PR.<x, y, z> = PolynomialRing(ZZ)

    # Maximal value of solution `x0`, `y0`, `z0`
    XX = floor(N^0.5)
    YY = floor(N^(alpha - 0.5))
    ZZ = floor(N^beta)

    # Norm of polynomial as vector representation
    WW = floor(N^(alpha + 0.5))

    # Some Non-negative real ([SAN10] 3.1 (11))
    tau = (1 - alpha - beta) / (2 * alpha - 1)

    # Powering degree
    mm = 4

    # Target polynomial
    pol = A - (d0 + x) * (u1 + y) + z
    x0, y0, z0 = jochemsz_may_trivariate(pol, XX, YY, ZZ, WW, tau, mm)

    # `d0 + x0` is secret exponents. so, `e` * `d0 + x0` equivalent to 1 modulo `\phi(n)`.
    d = d0 + x0
    assert (Mod(0xdeadbeefcafebabe, N)^e)^d == 0xdeadbeefcafebabe

    print ('[+] d = %d' % d)

    print(long_to_bytes(power_mod(c, d, N)))

```

## strange_classic 

### 出题idea

> 最早的出题思路来源于很早之前复现图灵攻击Enigma密码机时的思路，故题目名称为strange_classic，而hint名则为记录了这一事件的图灵传记电影“模仿游戏”。

​		Enigma密码机的加密可以抽象为$P = F^{-1}RF$, 图灵攻击Enigma密码机时的思路是考虑在明密文对中寻找能够构成首位相同的链，从而得到部分$P^n(x) = x$ 的情况，此时即有$R^n(F(x)) = F(x)$，这样只需要爆破 $R$ 函数相关的设定，大大降低了爆破的复杂度。

​		参考这一思路，于是我想把Enigma密码机中的 $F, R$ 换一换。首先整个变换是在 $GF(N)$ 上的，这里的 $F$ 直接使用一个可逆变换即可，这里为了方便使用一个可逆矩阵，$R$ 则使用的是基于多项式的流密码，本身也可以表示为多项式对应友矩阵的幂。考虑如果找到足够多的向量 $x_i, i = 1, 2, \dots$， 使得 $R^n(F(x_i)) = k_i*F(x_i)$， 那么向量 $F(x_i)$ 则为矩阵 $R^n$ 的特征向量，$k_i$ 即为特征值，得到了n组线性无关且符合上述等式的 $x_i$ 后，即获得了 $R^n$ 的特征值。我们可以由此构造出与 $R^n$ 相似的对角矩阵 $T^n$ ，$R^n \sim T^n$， 有 $R \sim T$，故我们只需要把 $R^n$ 的特征值在模$N$上开$n$ 次根即可得到 $R$ 的特征值，从而得到 $R$ 的特征方程即得到strange_classic的flag。

​		但是有个问题，对于矩阵 $R$ 的特征向量 $r_i$，一定也为 $R^n$ 的特征向量，如果想要找到 $x_i$，则需要能区分其特征向量的特点。而想要区分这一点，需要将加密n次的向量和加密其余次数特征向量区分开来， 需要构造一个与 $R$ 矩阵可交换的矩阵 $G$，$G$ 会改变 $R$ 的特征向量，但 $G^n$ 不改变 $R$ 的特征向量，即有 $G \neq I, G^n = I$。

​		最简单的情况是直接给一个数量矩阵 $g * I$，只要 $g^n = 1$ 即可，但这样并不能起到区分的作用，所以不能为数量矩阵。经过推导发现，由于 $R$ 矩阵为友矩阵，故任意矩阵 $G$，设置好 $G$ 最后一列的数据，其余数据由 $R$ 中的 $c_i$ 约束直接得出。由此，可以构造出一个非数量矩阵的与 $R$ 矩阵可交换的矩阵 $G$，随机选取 $G$ 的最后一列数据，得到 $G$ 有 $\frac{N-1}{N}$ 的概率不为0。而由于 $G$ 与 $R$ 可交换，故 $G$ 的任意次幂与 $R$ 也可交换。接下来需要研究有限域上矩阵的阶。如果 $G_{i\times i}$ 在 $GF(N)$ 上有 $i$ 个不同的特征值，则存在 $m$ 使得 $G^m = I$。而由于 $G$ 只由最后一列，即 $i$ 个元素决定，可以藉由这 $i$ 个变量表示出特征方程。给定一个有 $i$ 个不同根的多项式，通过系数联立，则可以得到 $i$ 方程，由此解出矩阵 $G$。但由于是有限域上多元高次方程，本身就是困难问题，所以考虑将模数设的小一些，然后爆破部分变量寻找符合的矩阵，这样矩阵的阶为 $\phi(N)*N$ 的因子，最终选取 $G' = G^{\frac{N*\phi N}{n}}$，则有 $G'^n = I$。为了不要在生成密文上耗费太多时间，由于$G'$ 的设置，存在 $n\ | \ \phi(N)$ ，故在模 $N$ 上开 $n$ 次根时，会出现 $n-1$ 个假根，为了降低爆破复杂度，选取特征值时，需注意不同特征值的 $n$ 次根不相等，最终只需要进行一个 $GCD(m*n, \phi(N))^m$ 的爆破即可，最后选取 $N = 43, m = 9, n = 3$。

​		最终的加密为 $P(x) = F^{-1}((F\cdot x)\cdot R^m \cdot G')$，梳理一遍整体的破解思路：

1. 寻找明文密文对中能构成长度为n的链
2. 得到 $m$ 个 $x_j$ 满足 $((F\cdot x_j) \cdot R^{m*n} \cdot G'^n) = k_j(F\cdot x_j) \Rightarrow ((F \cdot x_j) \cdot R^{m*n}) = k_j(F\cdot x_j)$
3. 将 $m$ 个 $k_j$ 在模 $N$ 上开 $m*n$ 次根，爆破 $n^m$ 种 $R$ 特征值的可能，从而得到 flag。

​		之后开始思考怎么让选手会往预期的思路上去靠，因为不可能直接暴露 $G'$，所以只能提示 $G$ 与 $R$ 可交换，且 $G$ 的特征值均落在 $GF(N)$ 上，并且使用的 $G' = G^{\frac{N*(N-1)}{3}}$，也提示了 $n$ 为3。

​		由于给出了flag的hash值方便爆破，考虑选手直接爆破特征值的复杂度为 $43^9 > 2^{48}$，36h的比赛中大概是够了。同时密文给出了4倍的冗余数据，并且没出成交互题限制时间，希望能看到有意思的非预期。
        
​		赛后发现，数据的特点导致部分选手认为可能$C^{27} = I$，产生了误导，没有很好的能跟正常的情况区分开，虽然爆破一遍也可以知道不对，但是还是我的失误，应该加个assert C^27 != I。

### exp

代入数据即可

```python=
from sage.all import *
from Crypto.Util.number import *
from hashlib import sha1


def is_k(v0, v1):
    judge = v0[0] * inverse(v1[0], N) % N
    for w in range(1, len(v1)):
        if v0[w] * inverse(v1[w], N) % N != judge:
            return False
    return judge


def find_k(plain_texts, cipher_texts):
    k = []
    for i in range(len(plain_texts)):
        if plain_texts[i] in cipher_texts and cipher_texts[i] in plain_texts:
            xi = plain_texts[cipher_texts.index(plain_texts[i])]
            xj = cipher_texts[plain_texts.index(cipher_texts[i])]
            tmp_k = is_k(xj, xi)
            if tmp_k:
                k.append(tmp_k)
    return k


def get_t(roots):
    PR = PolynomialRing(GF(N), 'x')
    x = PR.gens()[0]
    fx = 1
    for i in range(m):
        fx *= (x - roots[i])
    t = [int(-i % N) for i in fx.coefficients()[:-1]]
    return t


def get_possible_roots(y, e):
    roots = []
    for i in range(N):
        if i ** e % N == y:
            roots.append(i)
    return roots


N = 43
m = 9
n = 3
plain = 
cipher = 
hash = 'fd1f241a4d3ff9fc25d1e2480baa8b0c3b5a4559'
all_k = list(set(find_k(plain, cipher)))
assert len(all_k) == m
all_roots = [get_possible_roots(ki, n * m) for ki in all_k]

all_possible_t = []
for j in range(n**m):
    index = []
    tmp = j
    for _ in range(m):
        index.append(tmp % n)
        tmp //= n
    all_possible_t.append([all_roots[i][index[i]] for i in range(len(all_roots))])
for j in range(len(all_possible_t)):
    flag = 'MRCTF{%s}' % sha1(str(get_t(all_possible_t[j])).encode()).hexdigest()
    if sha1(flag.encode()).hexdigest() == hash:
        print('Got the flag:', flag)
        break
```

## strange_classic_revenge

### 出题idea

> 在strange_classic中，主要应用的性质即是矩阵的特征值在相似变换下不变。于是在revenge中，想要更进一步，通过某些变换下不变的格的性质恢复格。

​		对于由格基矩阵 $B_{n\times n}$ 张成的格 $L$，考虑一个可逆矩阵 $U$, $B' = U \cdot B$，则以 $B'$ 为格基矩阵的格 $L'$ 为格 $L$ 的子格。子格的行列式必然为原格行列式的倍数，而如果取 $n$ 个线性无关的不同子格的向量 $v_i$，则以 $v_i$ 为基的格 $L''$ 同样为 $L$ 的子格。

​		理论上，只要泄露了足够多随机向量 $r_i \cdot B$ 的结果，则可以通过组合不同的子格 $L_i$ 求行列式，再求最大公因数来获得原格的行列式。之后可以不断的给子格中添加向量，并计算Hermite标准型，然后判断行列式是否等于原格行列式，从而得到原格的信息，但直接考这个未免太简单了。

​		考虑如果得到了与 $B$ 中部分向量正交的向量集，通过组合则可以获得以格 $L$ 为子格的格。例如，对于格基矩阵 $B = \begin{bmatrix}\vec b_0\\ \vec b_1\\ \vdots\\ \vec b_{n-1} \end{bmatrix}$ ，可以获得了 $B_0 = \begin{bmatrix}\vec b_0\\ \vec b_1\\ \vdots\\ \vec b_{j} \end{bmatrix}$ 的解空间的基 $\vec v_0, \vec v_1, \dots, \vec v_j$， 则可以求出 $\vec v_0, \vec v_1, \dots, \vec v_j$ 构成齐次方程的解空间的基 $\begin{equation} \vec{b_0'}, \dots, \vec{b_j'} \end{equation}$。同样对于 $B_1 = \begin{bmatrix}\vec b_{j+1}\\ \vec b_{j+2}\\ \vdots\\ \vec b_{n-1} \end{bmatrix}$ 可以求出其解空间的解空间的基 $\vec b_{j+1}', \dots, \vec b_{n-1}'$ 。以 $\begin{equation} \vec{b_0'}, \dots, \vec{b_j'} \end{equation}$ 为基构成的格 $\mathbb{L}$ 以 $L$ 为子格。由此，如果我们可以得到一个格 $L$ 的多个子格 $L_i$ 的解空间的基 $\vec v_0, \vec v_1, \dots, \vec v_{n-1}$，如果格 $L$ 的行列式为素数，则可以恢复出格 $L$。

​		如果有多个随机向量乘格基矩阵的结果 $r_i$， 给出 $f(r_i)$，需要利用 $f(r_i)$ 求出$r_i$ 对应解空间的基，再利用上述方法恢复出格 $L$ 。最终使用$f(r_i, r_j) = (\sqrt{|r_{i,0}\cdot r_{j,0}|}, \sqrt{|r_{i,1}\cdot r_{j,1}|}, \dots, \sqrt{|r_{i,n-1}\cdot r_{j,n-1}|}) + \sum w_k r_k$ ，其中 $w_i$ 为随机数，其实这里的$\sqrt{|r_{i,0}\cdot r_{j,0}|}$随便给个同样比特大小的随机数都行，因为重点是如果$<k, r_i> = 0$，则有$<k, <w, r_i>> = <w, <k, r_i>> = 0$。以多个 $f(r_i, r_j)$ 构造垂直格, 规约出的向量即落在了 $r_i, \dots, r_{n-1}$ 的解空间上，得到足够多个即得到了解空间，再应用上面方法，即可得到原格。

### exp

```python=
from sage.all import *
from hashlib import sha1


Bits = 16
m = 32
K = 2


def get_orthogonal_basis(B):
    M = block_matrix(ZZ, [B, identity_matrix(B.nrows())], ncols=2)
    return M.LLL()[:m//2, -m:]


sub_lattice = []
cipher = 
for i in range(len(cipher)):
    mix0, mix1 = cipher[i]
    my_A0k = get_orthogonal_basis(Matrix(mix0).transpose())
    my_A1k = get_orthogonal_basis(Matrix(mix1).transpose())
    sub_lattice.append(block_matrix([Matrix(my_A0k.right_kernel().basis()), Matrix(my_A1k.right_kernel().basis())], nrows=2))

L2 = block_matrix(ZZ, sub_lattice, nrows=K)
print('MRCTF{%s}' % sha1(str(L2.hermite_form()[:m]).encode()).hexdigest())
```



## FlowerNTRU

### Introduction
本题目是根据原始NTRU改编的名为DBTRU的算法，相较于原始NTRU，DBTRU算法号称相同安全强度下密钥更短。然而，当加密参数选取不当时，会产生一系列问题，最严重可以使得唯密文攻击成立。本题目便是采用了这样的非安全参数，留下了巨大风险。

算法的具体流程以及正确性证明可以查阅原始paper：《DBTRU, a new NTRU-like cryptosystem based on dual binary truncated polynomial rings》，这里我们只关注攻击点。

### Analyze

算法中，加密流程为$e=(\varphi_0*h+S*\sum\varphi_i+m)\ mod\ L$，其中S和L是$x^{209}+1,x^{1019}+1$，$\varphi$的长度为401，$m$的长度更小，这导致的一个问题就是$\varphi_0*h$的高位直接暴漏在密文中。由于密文运算是在模L商环，因此密文的每一位运算都涉及了$\varphi$和$h$的每一位，因此只要泄露长度足够，就可以解出$\varphi_0$。有了$\varphi_0$，就能直接解明文。

### Experience

在实际计算中，所列的方程是在$Z_2$上，其系数矩阵由公钥h组成，在构造矩阵过程中，可能会出现不满秩导致的攻击失败。本题目方程数量比未知量数量多，可以直接使用所有方程直接解，也可以不断插入方程并实时判断是否满秩，再消除0行。实践过程方案因人而异，不一一列举。

exp如下：
```python
#type:ignore
# sagemath 9.3

from random import shuffle, randint
from tqdm import trange

s = 209
l = 1019
dphi = 401
dg = 500
Nf = 3
Nphi = 4

df = s - 1

PR.<x> = PolynomialRing(GF(2))
Rs.<x1> = QuotientRing(PR, PR.ideal(x^s + 1))
Rl.<x2> = QuotientRing(PR, PR.ideal(x^l + 1))


S = x^s + 1
L = x^l + 1


import time
from Crypto.Util.number import long_to_bytes


publicKey = load("publicKey.sobj")
e = load("e.sobj")

Field = GF(2)

start = time.time()
h = publicKey[2]
_h = [each for each in h]
pols = []
i = 0
while True:
    k = l - 1 - i
    this = _h[k-dphi+1:k+1][::-1]
    pols.append(this)
    if Matrix(Field, pols).rank() >= dphi:
        break
    i += 1
    if i == l:
        raise ValueError("Cannot get full rank matrix. Failed")

polMatrix = block_matrix(Field, [Matrix(Field, pols), (-1 * Matrix(Field, e.list()[l-1:l-1-len(pols):-1])).T], ncols=2, subdivide=False)
if polMatrix[:dphi].rank() < dphi:
    
    print("not full, using hermite form")
    polMatrix = polMatrix.hermite_form()[:dphi]
print(polMatrix.dimensions())

A = polMatrix.submatrix(0, 0, dphi, dphi)
y = polMatrix.submatrix(0, dphi, dphi, 1)
values = A.solve_right(y)
values = [int(each) for each in values.T.list()]
recovered = Rl(values)

print("Recovered phi:")
print(recovered)

m = (e - recovered * h)
m = PR([each for each in m]) % S

msg = int(''.join([str(each) for each in m][::-1]), 2)
msg = long_to_bytes(msg)

end = time.time()

print("Recovered message:")
print(msg)
print(end - start)
```


## FlowerBlockCipher

### Introduction

出题思路源于之前某场比赛中魔改的一个convert函数。在著名的python random模块攻击中，需要对convert函数进行逆向操作，而后来遇到的一场比赛使用了更加复杂的convert函数，然而这个函数仍然可以进行逆向计算。结合该函数的输入输出长度固定，非常像分组加密，因此就出了这样一道使用差分分析的分组密码题目。

### Analyze

该分组算法使用6轮加密，每一轮都会计算`cipher = convert1(cipher) ^ convert2(cipher) ^ subkey[0]`，如果需要进行差分分析的话，需要构造convert函数的异或同态运算。
在实践中，可以看出convert1本身是异或同态，即`convert1(a^b, iv) == convert1(a, iv) ^ convert1(b, iv)`，而对于convert2函数，有`convert2(a^b, iv) ^ MASK == convert2(a, iv) ^ convert2(b, iv)`，因此我们若要通过`convert2(a, iv)`和`convert2(b, iv)`得到`a^b`，需要计算`_convert2(convert2(a, iv) ^ convert2(b, iv) ^ MASK)`来恢复。又已知flag前六字节，通过爆破flag的7、8字节，整个加密便可以进行差分分析。

### Experience

实际出题过程中，原本并没有使用多轮运算，后来Nairw发现不使用多轮计算可以直接通过已知明文计算出加密密钥，失去了差分分析的灵魂。所以自己糊弄了一个轮计算、子密钥生成。当然，加入代换和置换也不会影响差分分析，但实际意义不大。

exp如下：
```python
def _recover(secret, iv, MASK, bitlength = 64):
    AND = (1 << iv) - 1
    result = [(secret ^ MASK) & AND]
    prev = result[0]
    secret >>= iv
    MASK >>= iv
    
    
    for _ in range(bitlength // iv):
        this = (prev & (MASK & AND)) ^ (prev | (MASK & AND))
        result.append(this ^ (secret & AND))
        prev = this ^ (secret & AND)
        secret >>= iv
        MASK >>= iv
    
    
    if bitlength % iv != 0:
        mask = (1 << bitlength % iv) - 1
        this = (prev & (MASK & mask)) ^ (prev | (MASK & mask))
        result.append(this ^ (secret & mask))
    
    ret = 0
    result.reverse()
    for each in result:
        ret = (ret << iv) + each
    
    return ret & ((1 << bitlength) - 1)

def recover(secret, iv, MASK, bitlength = 64):
    ret = secret
    for _ in range(6):
        ret = _recover(ret ^ MASK, iv, MASK, bitlength)
    return ret

ciphers = [16275631981232834393, 2330001200170040167, 4086054308230539023, 13797729999347054617, 14452975623657993541]
iv = 7
MASK = 14666605919630068755

diffs = []
for i in range(1, 5):
    this = ciphers[i] ^ ciphers[0]
    diffs.append(recover(this, iv, MASK))

import string
from Crypto.Util.number import long_to_bytes, bytes_to_long
import itertools as it
charset = string.ascii_letters

first_block = b'MRCTF{'
iter = it.product(charset, repeat=2)
for each in iter:
    this = bytes_to_long(first_block + (''.join(each)).encode())
    flag = long_to_bytes(this)
    for diff in diffs:
        flag += long_to_bytes(this ^ diff)
    
    if flag[-1] == 125:
        print(flag)
```