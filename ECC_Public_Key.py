import math
import random
import numpy as np
import matplotlib.pyplot as plt

def extendedGCD(a, b):
    if a == 0:
        return(b, 0, 1)
    else:
        g, x, y = extendedGCD(b % a, a)
        return (g, (y - (b // a) * x), x)

def mod_inverse(a, n):
    gcd, x, y = extendedGCD(a, n)
    if gcd != 1:
        raise Exception("GCD(a, n) =/= 1 : Modular Multiplicative Inverse Does Not Exist")
    else:
        return x % n

def plotECC(points_list, p):
    X = [point[0] for point in points_list]
    Y = [point[1] for point in points_list]
    fig = plt.figure(figsize = (8, 8), dpi = 100)
    plt.scatter(X, Y)
    plt.grid()
    plt.show()

def pointGenECC(a, b, p):
    points_list = []
    #y2 mod p = x3 + ax + b mod p
    for x in range(p):
        for y in range(p):
            Y = (y ** 2) % p
            X = ((x ** 3) + (a * x) + b) % p
            if Y == X:
                points_list.append((x, y))
    return points_list

def addTwoPoints(P, Q, a, b, p):
    #If P = -Q then return O.
    if (P[0] == Q[0]) and (P[1] == (p - Q[1])):
        return (0, 0)
    #If P = Q
    if P[0] == Q[0]:
        inv = mod_inverse(2 * P[1], p)
        lamda = (((3 * (P[0] ** 2)) + a) * inv) % p
    #If P != Q
    else:
        x = (Q[0] - P[0])
        y = (Q[1] - P[1])
        if y < 0:
            if x < 0:
                x = abs(x)
                y = abs(y)
            inv = mod_inverse(x, p)
        else:
            if x < 0:
                x = (p - x)
                inv = (-1) * mod_inverse(x, p)
            else:
                inv = mod_inverse(x, p)
        lamda = (y * inv) % p
        
    R_x = ((lamda ** 2) - P[0] - Q[0]) % p
    R_y = ((lamda * (P[0] - R_x)) - P[1]) % p

    return (R_x, R_y)

def multiplyScalarToPoint(P, k, a, b, p):
    R = P
    for i in range(k - 1):
        R = addTwoPoints(R, P, a, b, p)
    return R

def orderOfPoint(P, a, b, p):
    count = 1
    R = P
    while True:
        R = addTwoPoints(R, P, a, b, p)
        count += 1
        if R[0] == 0 and R[1] == 0:
            break
    return count

def keygenECC(base_point, a, b, p):
    n = orderOfPoint(base_point, a, b, p)
    print('\n*** ECC KEY GENERATION ***')
    private_key_alice = random.randint(1, n - 1)
    public_key_alice = multiplyScalarToPoint(base_point, private_key_alice, a, b, p)
    print('Private Key Alice : {}  Public Key Alice : {}'.format(private_key_alice, public_key_alice))
    private_key_bob = random.randint(1, n - 1)
    public_key_bob = multiplyScalarToPoint(base_point, private_key_bob, a, b, p)
    print('Private Key Bob : {}  Public Key Bob : {}'.format(private_key_bob, public_key_bob))
    return private_key_alice, public_key_alice,  private_key_bob, public_key_bob 

def encryptECC(base_point, M, P, a, b, p):
    n = orderOfPoint(base_point, a, b, p)
    k = random.randint(1, n - 1)
    print('k = ', k)
    C1 = multiplyScalarToPoint(base_point, k, a, b, p)
    R = multiplyScalarToPoint(P, k, a, b, p)
    C2 = addTwoPoints(M, R, a, b, p)
    print('Plain Text (M) = ', M)
    print('Cipher Text (c1, C2) = ', (C1, C2))
    return C1, C2

def decryptECC(C1, C2, P, a, b, p):
    C1 = multiplyScalarToPoint(C1, P, a, b, p)
    C1 = (C1[0], (p - C1[1]))
    M = addTwoPoints(C1, C2, a, b, p)
    print('M = ', M)
    return M

def controllerECCKeyExchange():
    p = 257
    a = 0
    b = -4
    points_list = pointGenECC(a, b, p)
    base_point = (2, 2)
    print('*** ECC PARAMETERS ***')
    print('ELLIPTIC CURVE (Zp) : E(p : {})({}, {})'.format(p, a, b))
    print('Base Point (G) : ', base_point)
    n = orderOfPoint(base_point, a, b, p)
    print('Order of G : ', n)
    private_key_alice, public_key_alice,  private_key_bob, public_key_bob  = keygenECC(base_point, a, b, p)
    print()
    print('*** ECC ENCRYPTION ***')
    C1, C2 = encryptECC(base_point, (112, 26), public_key_bob, a, b, p)
    print()
    print('*** ECC DECRYPTION ***')
    M = decryptECC(C1, C2, private_key_bob, a, b, p)
    plotECC(points_list, p)

if __name__ == '__main__':
    controllerECCKeyExchange()
