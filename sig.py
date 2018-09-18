from charm.toolbox.pairinggroup import PairingGroup

'''
Dan Boneh, Xavier Boyen, and Hovav Shacham

| From: "Short Group Signatures
| Published in: CRYPTO 2004
| Available from: n/a
| Notes: An extended abstract of this paper appeared in Advances in Cryptology (2004)

* type:           digital signature scheme
* setting:        Pairing

:Authors:    J Ayo Akinyele
:Date:           12/2010
'''
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.PKSig import PKSig
import time

debug = False


class ShortSig(PKSig):

    def __init__(self, groupObj):
        PKSig.__init__(self)
        global group
        group = groupObj

    def keygen(self, n):
        g1, g2 = group.random(G1), group.random(G2)
        h = group.random(G1)
        xi1, xi2 = group.random(), group.random()

        u, v = h ** ~xi1, h ** ~xi2
        gamma = group.random(ZR)
        w = g2 ** gamma
        gpk = {'g1': g1, 'g2': g2, 'h': h, 'u': u, 'v': v, 'w': w}
        gmsk = {'xi1': xi1, 'xi2': xi2}

        x = [group.random(ZR) for i in range(n)]
        A = [gpk['g1'] ** ~(gamma + x[i]) for i in range(n)]
        gsk = {}
        if debug: print("\nSecret keys...")
        for i in range(n):
            if debug: print("User %d: A = %s, x = %s" % (i, A[i], x[i]))
            gsk[i] = (A[i], x[i])
        return (gpk, gmsk, gsk,gamma)

    def sign(self, gpk, gsk, M):
        alpha, beta = group.random(), group.random()
        A, x = gsk[0], gsk[1]
        T1 = gpk['u'] ** alpha
        T2 = gpk['v'] ** beta
        T3 = A * (gpk['h'] ** (alpha + beta))

        delta1 = x * alpha
        delta2 = x * beta
        r = [group.random() for i in range(5)]

        R1 = gpk['u'] ** r[0]
        R2 = gpk['v'] ** r[1]
        R3 = (pair(T3, gpk['g2']) ** r[2]) * (pair(gpk['h'], gpk['w']) ** (-r[0] - r[1])) * (
                pair(gpk['h'], gpk['g2']) ** (-r[3] - r[4]))
        R4 = (T1 ** r[2]) * (gpk['u'] ** -r[3])
        R5 = (T2 ** r[2]) * (gpk['v'] ** -r[4])

        c = group.hash((M, T1, T2, T3, R1, R2, R3, R4, R5), ZR)
        s1, s2 = r[0] + c * alpha, r[1] + c * beta
        s3, s4 = r[2] + c * x, r[3] + c * delta1
        s5 = r[4] + c * delta2
        return {'T1': T1, 'T2': T2, 'T3': T3, 'c': c, 's_alpha': s1, 's_beta': s2, 's_x': s3, 's_delta1': s4,
                's_delta2': s5}

    def verify(self, gpk, M, sigma):
        validSignature = False

        c, t1, t2, t3 = sigma['c'], sigma['T1'], sigma['T2'], sigma['T3']
        s_alpha, s_beta = sigma['s_alpha'], sigma['s_beta']
        s_x, s_delta1, s_delta2 = sigma['s_x'], sigma['s_delta1'], sigma['s_delta2']

        R1_ = (gpk['u'] ** s_alpha) * (t1 ** -c)
        R2_ = (gpk['v'] ** s_beta) * (t2 ** -c)
        R3_ = (pair(t3, gpk['g2']) ** s_x) * (pair(gpk['h'], gpk['w']) ** (-s_alpha - s_beta)) * (
                pair(gpk['h'], gpk['g2']) ** (-s_delta1 - s_delta2)) * (
                      (pair(t3, gpk['w']) / pair(gpk['g1'], gpk['g2'])) ** c)
        R4_ = (t1 ** s_x) * (gpk['u'] ** -s_delta1)
        R5_ = (t2 ** s_x) * (gpk['v'] ** -s_delta2)

        c_prime = group.hash((M, t1, t2, t3, R1_, R2_, R3_, R4_, R5_), ZR)

        if c == c_prime:
            if debug: print("c => '%s'" % c)
            if debug: print("Valid Group Signature for message: '%s'" % M)
            validSignature = True
        else:
            if debug: print("Not a valid signature for message!!!")
        return validSignature

    def open(self, gpk, gmsk, M, sigma):
        t1, t2, t3, xi1, xi2 = sigma['T1'], sigma['T2'], sigma['T3'], gmsk['xi1'], gmsk['xi2']

        A_prime = t3 / ((t1 ** xi1) * (t2 ** xi2))
        return A_prime

    def revoke(self,gpk,gsk,gamma):

        rk=(gsk[0],gpk['g2'] ** ~(gamma + gsk[1]),gsk[1])
        return rk
    #RK=(A[i],A_star[i],x[i]

    def udgpk(self, gpk, gamma, rk):
        g1_prime = rk[0]
        g2_prime = rk[1]
        w_prime = gpk['g2'] * (rk[1] ** (-rk[2]))
        gpk['g1'] = g1_prime
        gpk['g2'] = g2_prime
        gpk['w'] = w_prime
        # gpk = {'g1': g1_prime, 'g2': g2_prime, 'h': gpk['h'], 'u': gpk['u'], 'v': [v, 'w': w_prime}
        return gpk

    def batch_udgpkrl(self,gpk,gamma,upd):
        t=1
        RL={}
        for i in range(len(upd)):
            t=t*(gamma+upd[i])
            RL[i]=(gpk['g1']**~t, gpk['g2']**~t,upd[i])

        g1_prime=gpk['g1']**~t
        g2_prime=gpk['g2']**~t
        w_prime=g2_prime**gamma
        gpk['g1']=g1_prime
        gpk['g2']=g2_prime
        gpk['w']=w_prime
        #gpk = {'g1': g1_prime, 'g2': g2_prime, 'h': gpk['h'], 'u': gpk['u'], 'v': [v, 'w': w_prime}
        return (gpk,RL)

    def batch_udgsk(self,gsk,RL):
        gsk_prime=gsk
        for i in range(len(RL)):
            gsk_prime=self.udgsk(gsk_prime,RL[i])
        return gsk_prime

    def udgsk(self,gsk,rk):
        s1=rk[0] ** ~(gsk[1] - rk[2])
        s2=gsk[0] ** ~(gsk[1] - rk[2])
        A_prime=s1/s2
        gsk_prime=(A_prime,gsk[1])
        return gsk_prime

    def udCheck(self,gamma, gsk,gpk):
        if gsk[0]**(gamma+gsk[1]) == gpk['g1']:
            print('correct')
        else:
            print('incorrect')

def main():
    rev_num=100 #  number of revoked users
    sigGroup = PairingGroup('MNT224')
    n = 1000  # how manu users are in the group
    user = 0  # which user's key we will sign a message with
    shortSig = ShortSig(sigGroup)
    start=time.clock()
    (global_public_key, global_master_secret_key, user_secret_keys,gamma) = shortSig.keygen(n)
    elapsed=time.clock()-start
    print('time elapsed:',elapsed)

    msg = 'Hello World this is a message!'

    signature = shortSig.sign(global_public_key, user_secret_keys[user], msg)
    '''
    print '-------------before revocation----------------'
    start_Sign=time.clock()
    for i in range(100):
        signature = shortSig.sign(global_public_key, user_secret_keys[user], msg)
    elapsed_Sign = (time.clock() - start_Sign) / (100)
    print elapsed_Sign
    '''
    start_Verify = time.clock()
    for i in range(1000):
        flag=shortSig.verify(global_public_key, msg, signature)
    elapsed_Verify = (time.clock() - start_Verify) / (1000)
    print elapsed_Verify

    '''
    elapsed_timeOpen = ''
    start_Open = time.clock()
    for j in range(10):
        for i in range(100):
            shortSig.open(global_public_key, global_master_secret_key, msg, signature)
        elapsed_Open = (time.clock() - start_Open) / (100)
        elapsed_timeOpen += str(elapsed_Open) + '\t'
    print'Open time elapsed:', elapsed_timeOpen
    '''
    print '-------------after revocation----------------'
    #rk = shortSig.revoke(global_public_key, user_secret_keys[user], gamma)

    #print upd
    '''
    elapsed_timeudgpk=''
    elapsed_timeudgsk = ''
    for i in range(10,rev_num+1,10):
        upd = {}
        for j in range(i):
            upd[j] = user_secret_keys[j][1]

        # update gpk and Revocation List
        start_udgpk= time.clock()
        for k in range(10):
            (global_public_key_prime,RL)=shortSig.batch_udgpkrl(global_public_key, gamma,upd)
        elapsed_udgpk = (time.clock() - start_udgpk)/10
        #print i,elapsed_udgpk
        # print(i, elapsed_udgpk)
        elapsed_timeudgpk += str(elapsed_udgpk) + '\t'


        # update gsk
        start_udgsk = time.clock()
        for k in range(10):
            gsk_prime = shortSig.batch_udgsk(user_secret_keys[user + rev_num], RL)
        elapsed_udgsk = (time.clock() - start_udgsk)/10
        #print i, elapsed_udgsk
        elapsed_timeudgsk+= str(elapsed_udgsk) + '\t'
        #print(i, elapsed_udgsk)
    print elapsed_timeudgpk
    print elapsed_timeudgsk
    '''

    #global_public_key_prime2 = shortSig.udgpk(global_public_key, gamma, RL[0])
    #print global_public_key_prime['g1']==global_public_key_prime2['g1']
    #print global_public_key_prime['g2'] == global_public_key_prime2['g2']
    #print global_public_key_prime['w'] == global_public_key_prime2['w']
    #print '-----------------'



    #gsk_prime2 = shortSig.udgsk(user_secret_keys[user + 10], rk)
    #print gsk_prime[0]==gsk_prime2[0]
    #print gsk_prime[1]==gsk_prime2[1]
    #print gsk_prime==gsk_prime2

    #print '---------------'
    #shortSig.udCheck(gamma, gsk_prime, global_public_key_prime)
    #shortSig.udCheck(gamma, gsk_prime2, global_public_key_prime2)

    #rk=shortSig.revoke(global_public_key,user_secret_keys[user],gamma)
    #global_public_key_prime=shortSig.udgpk(global_public_key,gamma,rk)
    #gsk_prime=shortSig.udgsk(user_secret_keys[user+2],rk)

   # print '---------------'
#    signature = shortSig.sign(global_public_key_prime, gsk_prime, msg)
   # print(shortSig.verify(global_public_key_prime, msg, signature))



if __name__ == "__main__":
    main()