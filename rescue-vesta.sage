load("instance_generator.sage")

##########################################################
## rescue_vesta parameters
##########################################################

## Field over which rescue functions
q_vesta = 28948022309329048855892746252171976963363056481941647379679742748393362948097

## Create parameters for F_{q_vesta} with state width 4 and \alpha = 5
rescue_vesta = Rescue(128, q_vesta, 4, 5)

# return the permutation constant in hex form 
# This is the BlockCipher method from ../instance_generator.sage considering only the keys
def permutation_round_keys():

    # use a fixed key [0,0,0,0]
    key_state = matrix(rescue_vesta.F, [[rescue_vesta.F.zero()]] * rescue_vesta.m)

    key_injection = rescue_vesta.initial_constant
    key_state += key_injection

    # list to keep the round keys
    permutation_round_keys = []
    
    # store the hex values of keys
    permutation_round_keys.append([(s[0]) for s in key_state])

    for r in range(0, 2 * rescue_vesta.Nb):

        # constants for inverse SBOX
        if r % 2 == 0:
            for i in range(0,rescue_vesta.m):
                key_state[i,0] = key_state[i,0]^rescue_vesta.invalpha

        # constants for pow5 SBOX
        else:
            for i in range(0,rescue_vesta.m):
                key_state[i,0] = key_state[i,0]^rescue_vesta.alpha
        key_injection = rescue_vesta.constants_matrix * key_injection + rescue_vesta.constants_constant

        key_state = rescue_vesta.MDS * key_state + key_injection

        # append the key
        permutation_round_keys.append([(s[0]) for s in key_state])

    return permutation_round_keys

# return the key injection constants in hex form 
def ki_vector():

    key_injection = rescue_vesta.initial_constant

    # list to keep the constant 
    ki_vector = []
    
    # store the hex values of keys
    ki_vector.append([(s[0]) for s in key_injection])

    for r in range(0, 2 * rescue_vesta.Nb):

      key_injection = rescue_vesta.constants_matrix * key_injection + rescue_vesta.constants_constant

      # append the key
      ki_vector.append([(s[0]) for s in key_injection])

    return ki_vector 

# create limb from string
def create_limb(str): 
    if len(str) == 0:
      return "0x0"
    else: 
      return "0x" + str

# Convert a hex number to 4 length 16 limbs in little endian
def convert_limbs(number):
    # remove "0x" prefix 
    number_hex = str(hex(number))[2::]
    limbs = []
    for _ in range(4):
        l, number_hex = number_hex[-16:], number_hex[:-16]
        limbs.append(create_limb(l))
    return limbs

###################################################################################
###################################### rounds #####################################

n_rounds = rescue_vesta.Nb

###################################################################################
###################################################################################


###################################################################################
#################################### inverse a ####################################

ainv = rescue_vesta.invalpha

# get the "canonical" form
while ainv < 0:
    ainv += (q_vesta - 1)
ainv = convert_limbs(ainv)

###################################################################################
###################################################################################


###################################################################################
####################################### MDS #######################################

# MDS 
mds = []
for i in range(0,4):
    mds_row = []
    for j in range(0,4):

        val = rescue_vesta.MDS[i][j]

        # get the "canonical" form
        while val < 0:
            val += (q_vesta)
        mds_row.append(convert_limbs(val))
    mds.append(mds_row)

###################################################################################
###################################################################################


###################################################################################
################################# Round Constants #################################

permutation_round_key = permutation_round_keys()

# initial constants
rc = []
rc.append([(convert_limbs(k)) for k in permutation_round_key[0]])

for i in range(2 * n_rounds):
    # start of round
    if i % 2 == 0:
      rc.append([(convert_limbs(k)) for k in permutation_round_key[i+1]])
    # end of round
    else:
      rc.append([(convert_limbs(k)) for k in permutation_round_key[i+1]])

###################################################################################
###################################################################################

###################################################################################
#################################### KI Vector ####################################

ki_vector = ki_vector()

# initial constants
ki = []
ki.append([(convert_limbs(k)) for k in ki_vector[0]])

for i in range(2 * n_rounds):
  ki.append([(convert_limbs(k)) for k in ki_vector[i+1]])

###################################################################################
###################################################################################


###################################################################################
################################# Test Vectors ####################################

# get random input state
def random_input():
    r = []
    for i in range(4):
      r.append([rescue_vesta.F.random_element()])
    return matrix(rescue_vesta.F, r)


# Get random inputs with fixed seed=0

set_random_seed(0)
inputs = [(random_input()) for _ in range(4)]

# Set a fixed 0 key
fixed_key = matrix(rescue_vesta.F, [[rescue_vesta.F.zero()]] * rescue_vesta.m)
zero_state = matrix(rescue_vesta.F, [[rescue_vesta.F.zero()]] * rescue_vesta.m)

pairs_raw = []

# compute output of [0,0,0,0]
pairs_raw.append((zero_state, rescue_vesta.BlockCipher(fixed_key, zero_state)))

# compute the output for the random pairs
pairs_raw.extend(list(map(lambda x: (x, rescue_vesta.BlockCipher(fixed_key, x)), inputs)))

# keyed variant
# sample random key, state pair
inputs = [(random_input(), random_input()) for _ in range(4)]

keyed_pairs_raw = []

# compute the output for the random pairs
keyed_pairs_raw.extend(list(map(lambda x: (x[0], x[1], rescue_vesta.BlockCipher(x[0], x[1])), inputs)))


# helper function to get the limbs from a state
# maps each of the elements of the state to its limbs
def limbs_from_state(state):
    limbs = []
    for el in state:
        limbs.append(convert_limbs(el[0]))
    return limbs
   


# get limbs from pairs:
pairs = []
for (input, output) in pairs_raw:
      pairs.append((limbs_from_state(input), limbs_from_state(output)))

# get limbs from keyed_pairs:
keyed_pairs = []
for (key, input, output) in keyed_pairs_raw:
      keyed_pairs.append((limbs_from_state(key),limbs_from_state(input), limbs_from_state(output)))

# compute the chain of 32 applications of the permutation on [0,0,0,0]
chain_state = zero_state
for i in range(32):
    chain_state = rescue_vesta.BlockCipher(fixed_key, chain_state)
chain_state = limbs_from_state(chain_state)

###################################################################################
###################################################################################


###################################################################################
################################ Print parameters #################################

print("N_ROUNDS = ")
pretty_print(n_rounds)
print("\n")

print("A_INV = ")
pretty_print(ainv)
print("\n")

print("MDS = ")
pretty_print(mds)
print("\n")


print("RC = ")
pretty_print(rc)
print("\n")

print("KI = ")
pretty_print(ki)
print("\n")

print("Test vectors = [")
pretty_print(pairs_raw)
print("\n")

print("Test vectors in limbs = [")
pretty_print(pairs)
print("\n")

print("Keyed test vectors in limbs = [")
pretty_print(keyed_pairs)
print("\n")

print("Chain of 32 permutation of [0,0,0,0] = [")
pretty_print(chain_state)
print("\n")
