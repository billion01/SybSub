from paillier.paillier import *
priv,pub=generate_keypair(128,20)
x=encrypt(pub,priv,3)
y=encrypt(pub,priv,4)
#print x,y
z=e_add(pub,x,y)
z1=e_mul_const(pub,x,4)
#print z,z1
print decrypt(pub,z)
print decrypt(pub,z1)
