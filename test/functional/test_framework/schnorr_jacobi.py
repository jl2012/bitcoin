#!/usr/bin/python3

import hashlib
import binascii

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, 1)

def point_dbl(p1):
    if p1 is None:
        return None
    y2 = (p1[1] * p1[1]) % p
    s = (4 * p1[0] * y2) % p
    m = (3 * p1[0] * p1[0]) % p
    x3 = (m * m - 2 * s) % p
    y3 = (m * (s - x3) - 8 * y2 * y2) % p
    z3 = (2 * p1[1] * p1[2]) % p
    return (x3, y3, z3)

def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    z12 = (p1[2] * p1[2]) % p
    z13 = (p1[2] * z12) % p
    z22 = (p2[2] * p2[2]) % p
    z23 = (p2[2] * z22) % p
    u1 = (p1[0] * z22) % p
    u2 = (p2[0] * z12) % p
    s1 = (p1[1] * z23) % p
    s2 = (p2[1] * z13) % p
    if (u1 == u2):
        if (s1 != s2):
            return None
        return point_dbl(p1)
    h = u2 - u1
    r = s2 - s1
    h2 = (h * h) % p
    x3 = (r * r - h2 * (h + 2 * u1)) % p
    y3 = (r * (u1 * h2 - x3) - s1 * h2 * h) % p
    z3 = (h * p1[2] * p2[2]) % p
    return (x3, y3, z3)

def point_x(p1):
    return (p1[0] * pow(p1[2], p - 3, p)) % p

def point_affine(p1):
    i = pow(p1[2], p - 2, p)
    i2 = (i * i) % p
    return ((p1[0] * i2) % p, (p1[1] * i * i2) % p)

def point_jacobi(p1):
    return pow(p1[1] * p1[2], (p - 1) // 2, p)

def point_bytes(b):
    x = int.from_bytes(b[1:], byteorder="big")
    y = pow((x*x*x + 7) % p, (p + 1) // 4, p)
    if (y & 1 != b[0] & 1):
        y = p - y
    return (x,y,1)

def point_mul(p, n):
    r = None
    for i in range(256):
        if ((n >> i) & 1):
            r = point_add(r, p)
        p = point_dbl(p)
    return r

def bytes_point(p):
    a = point_affine(p)
    return (b'\x03' if a[1] & 1 else b'\x02') + a[0].to_bytes(32, byteorder="big")

def sha256(b):
    h = hashlib.sha256()
    h.update(b)
    return int.from_bytes(h.digest(), byteorder="big")

def schnorr_sign(m, x):
    k = sha256(x.to_bytes(32, byteorder="big") + m)
    R = point_mul(G, k)
    if point_jacobi(R) != 1:
        k = n - k
    r = point_x(R).to_bytes(32, byteorder="big")
    e = sha256(r + bytes_point(point_mul(G, x)) + m)
    return r + ((k + e * x) % n).to_bytes(32, byteorder="big")

def schnorr_verify_1(m, P, sig):
    r = int.from_bytes(sig[0:32], byteorder="big")
    s = int.from_bytes(sig[32:64], byteorder="big")
    if r >= p or s >= n:
        return False
    e = sha256(sig[0:32] + bytes_point(P) + m)
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if point_jacobi(R) != 1:
        return False
    return (r * R[2] * R[2] - R[0]) % p == 0

def schnorr_verify_2(m, P, sig):
    r = int.from_bytes(sig[0:32], byteorder="big")
    s = int.from_bytes(sig[32:64], byteorder="big")
    if r >= p or s >= n:
        return False
    e = sha256(sig[0:32] + bytes_point(P) + m)
    c = (pow(r, 3, p) + 7) % p
    y = pow(c, (p + 1) // 4, p)
    if (y * y) % p != c:
        return False
    R = (r, y, 1)
    return point_add(point_mul(G, n - s), point_add(R, point_mul(P, e))) == None
