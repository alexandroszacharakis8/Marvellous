load("instance_generator.sage")

##########################################################
## rescue_pallas parameters
##########################################################

## Field over which rescue functions
q_pallas = 28948022309329048855892746252171976963363056481941560715954676764349967630337

## Create parameters for F_{q_pallas} with state width 4 and \alpha = 5
rescue_pallas = Rescue(128, q_pallas, 4, 5)

# return the permutation constant in hex form 
# This is the BlockCipher method from ../instance_generator.sage considering only the keys
def permutation_round_keys():

    # use a fixed key [0,0,0,0]
    key_state = matrix(rescue_pallas.F, [[rescue_pallas.F.zero()]] * rescue_pallas.m)

    key_injection = rescue_pallas.initial_constant
    key_state += key_injection

    # list to keep the round keys
    permutation_round_keys = []
    
    # store the hex values of keys
    permutation_round_keys.append([(s[0]) for s in key_state])

    for r in range(0, 2 * rescue_pallas.Nb):

        # constants for inverse SBOX
        if r % 2 == 0:
            for i in range(0,rescue_pallas.m):
                key_state[i,0] = key_state[i,0]^rescue_pallas.invalpha

        # constants for pow5 SBOX
        else:
            for i in range(0,rescue_pallas.m):
                key_state[i,0] = key_state[i,0]^rescue_pallas.alpha
        key_injection = rescue_pallas.constants_matrix * key_injection + rescue_pallas.constants_constant

        key_state = rescue_pallas.MDS * key_state + key_injection

        # append the key
        permutation_round_keys.append([(s[0]) for s in key_state])

    return permutation_round_keys


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

n_rounds = rescue_pallas.Nb

###################################################################################
###################################################################################


###################################################################################
#################################### inverse a ####################################

ainv = rescue_pallas.invalpha

# get the "canonical" form
while ainv < 0:
    ainv += (q_pallas - 1)
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

        val = rescue_pallas.MDS[i][j]

        # get the "canonical" form
        while val < 0:
            val += (q_pallas)
        mds_row.append(convert_limbs(val))
    mds.append(mds_row)

###################################################################################
###################################################################################


###################################################################################
################################# Round Constants #################################

permutation_round_key = permutation_round_keys()

# initial constants
ic = []
ic.append([(convert_limbs(k)) for k in permutation_round_key[0]])

# round constants at start and end of full round
rc_start = []
rc_end = []

for i in range(2 * n_rounds):
    # start of round
    if i % 2 == 0:
      rc_start.append([(convert_limbs(k)) for k in permutation_round_key[i+1]])
    # end of round
    else:
      rc_end.append([(convert_limbs(k)) for k in permutation_round_key[i+1]])

###################################################################################
###################################################################################


###################################################################################
################################# Test Vectors ####################################

# get random input state
def random_input():
    r = []
    for i in range(4):
      r.append([rescue_pallas.F.random_element()])
    return matrix(rescue_pallas.F, r)


# Get random inputs with fixed seed=0

set_random_seed(0)
inputs = [(random_input()) for _ in range(4)]

# Set a fixed 0 key
fixed_key = matrix(rescue_pallas.F, [[rescue_pallas.F.zero()]] * rescue_pallas.m)
zero_state = matrix(rescue_pallas.F, [[rescue_pallas.F.zero()]] * rescue_pallas.m)

pairs_raw = []

# compute output of [0,0,0,0]
pairs_raw.append((zero_state, rescue_pallas.BlockCipher(fixed_key, zero_state)))

# compute the output for the random pairs
pairs_raw.extend(list(map(lambda x: (x, rescue_pallas.BlockCipher(fixed_key, x)), inputs)))


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


print("RC_INITIAL = ")
pretty_print(ic)
print("\n")


print("RC_START = ")
pretty_print(rc_start)
print("\n")

print("RC_END = [")
pretty_print(rc_end)
print("\n")

print("Test vectors = [")
pretty_print(pairs_raw)
print("\n")

print("Test vectors in limbs = [")
pretty_print(pairs)
print("\n")
