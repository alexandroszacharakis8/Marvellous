load("instance_generator.sage")

##########################################################
## rescue_eris parameters
##########################################################

## Field over which rescue functions
eris_scalar = 102211695604070082112571065507755096754575920209623522239390234855490679834276115250716018318118556227909439196474813090886893187366913

## Create parameters for F_{eris_scalar} with state width 4 and \alpha = 5
rescue_eris = Rescue(128, eris_scalar, 4, 5)

# return the permutation constant in hex form 
# This is the BlockCipher method from ../instance_generator.sage considering only the keys
def permutation_round_keys():

    # use a fixed key [0,0,0,0]
    key_state = matrix(rescue_eris.F, [[rescue_eris.F.zero()]] * rescue_eris.m)

    key_injection = rescue_eris.initial_constant
    key_state += key_injection

    # list to keep the round keys
    permutation_round_keys = []
    
    # store the hex values of keys
    permutation_round_keys.append([(s[0]) for s in key_state])

    for r in range(0, 2 * rescue_eris.Nb):

        # constants for inverse SBOX
        if r % 2 == 0:
            for i in range(0,rescue_eris.m):
                key_state[i,0] = key_state[i,0]^rescue_eris.invalpha

        # constants for pow5 SBOX
        else:
            for i in range(0,rescue_eris.m):
                key_state[i,0] = key_state[i,0]^rescue_eris.alpha
        key_injection = rescue_eris.constants_matrix * key_injection + rescue_eris.constants_constant

        key_state = rescue_eris.MDS * key_state + key_injection

        # append the key
        permutation_round_keys.append([(s[0]) for s in key_state])

    return permutation_round_keys

# return the key injection constants in hex form 
def ki_vector():

    key_injection = rescue_eris.initial_constant

    # list to keep the constant 
    ki_vector = []
    
    # store the hex values of keys
    ki_vector.append([(s[0]) for s in key_injection])

    for r in range(0, 2 * rescue_eris.Nb):

      key_injection = rescue_eris.constants_matrix * key_injection + rescue_eris.constants_constant

      # append the key
      ki_vector.append([(s[0]) for s in key_injection])

    return ki_vector 

# create limb from string
def create_limb(str): 
    if len(str) == 0:
      return "0x00"
    else: 
      return "0x" + str

# Convert a hex number to 7 length 16 limbs in little endian
def convert_limbs(number):
    # remove "0x" prefix 
    number_hex = str(hex(number))[2::]
    limbs = []
    for _ in range(7):
        l, number_hex = number_hex[-16:], number_hex[:-16]
        limbs.append(create_limb(l))
    return limbs

###################################################################################
###################################### rounds #####################################

n_rounds = rescue_eris.Nb

###################################################################################
###################################################################################


###################################################################################
#################################### inverse a ####################################

ainv = rescue_eris.invalpha

# get the "canonical" form
while ainv < 0:
    ainv += (eris_scalar - 1)
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

        val = rescue_eris.MDS[i][j]

        # get the "canonical" form
        while val < 0:
            val += (eris_scalar)
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
      r.append([rescue_eris.F.random_element()])
    return matrix(rescue_eris.F, r)


# Get random inputs with fixed seed=0

set_random_seed(0)
inputs = [(random_input()) for _ in range(4)]

# Set a fixed 0 key
fixed_key = matrix(rescue_eris.F, [[rescue_eris.F.zero()]] * rescue_eris.m)
zero_state = matrix(rescue_eris.F, [[rescue_eris.F.zero()]] * rescue_eris.m)

pairs_raw = []

# compute output of [0,0,0,0]
pairs_raw.append((zero_state, rescue_eris.BlockCipher(fixed_key, zero_state)))

# compute the output for the random pairs
pairs_raw.extend(list(map(lambda x: (x, rescue_eris.BlockCipher(fixed_key, x)), inputs)))

# keyed variant
# sample random key, state pair
inputs = [(random_input(), random_input()) for _ in range(4)]

keyed_pairs_raw = []

# compute the output for the random pairs
keyed_pairs_raw.extend(list(map(lambda x: (x[0], x[1], rescue_eris.BlockCipher(x[0], x[1])), inputs)))

# Sponge Test Vectors. We sample 4 vectors of size 12. We use rate 3.
sponge_inputs_raw = [[rescue_eris.F.random_element() for _ in range(12)] for _ in range(4)]
sponge_inputs = [list(map(convert_limbs, x)) for x in sponge_inputs_raw]
sponge_outputs_raw = [rescue_eris.Sponge(input, 3) for input in sponge_inputs_raw]
sponge_outputs = [list(map(convert_limbs, x)) for x in sponge_outputs_raw]

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
    chain_state = rescue_eris.BlockCipher(fixed_key, chain_state)
chain_state = limbs_from_state(chain_state)

###################################################################################
###################################################################################

###################################################################################
################################# Counter mode ####################################

# Select random messages of length 4
set_random_seed(0)
messages = [(random_input()) for _ in range(4)]

counter_mode_msgs = [[list(map(convert_limbs, x)) for x in msg] for msg in messages]

# Select a random key
set_random_seed(1)
key = random_input()

# Start with zero input
input = matrix(rescue_eris.F, [[rescue_eris.F.zero()]] * rescue_eris.m)

outputs = copy(messages)

# Encrypt
for msg in outputs:
    key_stream = rescue_eris.BlockCipher(key, input)
    for i in range(4):
        msg[i] += key_stream[i]

    input[0,0] += rescue_eris.F(1)


counter_mode_key = [list(map(convert_limbs, x)) for x in key]
counter_mode_out = [[list(map(convert_limbs, x)) for x in out] for out in outputs]

###################################################################################
###################################################################################

###################################################################################
################################ Print parameters #################################

def print_scalar_slice(w):
    print("Fp::from_raw([")
    for m in w:
        print(m + ",")
    print("]),")

print("N_ROUNDS = ")
pretty_print(n_rounds)
print("\n")

print("const A_INV: Self::AInvType = [")
print_scalar_slice(ainv)
print("];\n")

print("const MDS: RescueMatrix<Fp> = [")
for out in mds:
    print("[")
    for ss in out:
        print_scalar_slice(ss)
    print("],")
print("];\n")

print("const RC_VECTOR: StateVectorsMatrix<Fp> = [")
for out in rc:
    print("[")
    for ss in out:
        print_scalar_slice(ss)
    print("],")
print("];\n")

print("const KI_VECTOR: StateVectorsMatrix<Fp> = [")
for out in ki:
    print("[")
    for ss in out:
        print_scalar_slice(ss)
    print("],")
print("];\n")

print("================\n")
print("= TEST VECTORS =\n")
print("================\n")

print("Chain of 32 permutation of [0,0,0,0] = [")
pretty_print(chain_state)
print("\n")

print("pub(crate) const ERIS_TEST_VECTORS: [InputOutputPair<Fp>; 5] = [")
for pair in pairs:
    print("([")
    for val in pair[0]:
        print_scalar_slice(val)
    print("],[")
    for val in pair[1]:
        print_scalar_slice(val)
    print("]),")
print("];\n")

print("pub(crate) const ERIS_TEST_VECTORS_KEYED: [KeyedInputOutputPair<Fp>; 4] = [")
for pair in keyed_pairs:
    print("([")
    for val in pair[0]:
        print_scalar_slice(val)
    print("],[")
    for val in pair[1]:
        print_scalar_slice(val)
    print("],[")
    for val in pair[2]:
        print_scalar_slice(val)
    print("]),")
print("];\n")

print("pub(crate) const ERIS_SPONGE_TEST_VECTORS: [([Fp; 12], [Fp; 3]); 4] = [")
for (input, output) in list(zip(sponge_inputs, sponge_outputs)):
    print("([")
    for val in input:
        print_scalar_slice(val)
    print("],[")
    for val in output:
        print_scalar_slice(val)
    print("]),")
print("];\n")

print("pub(crate) const ERIS_COUNTER_MODE_MSG: [[Fp; 4]; 4] = [")
for out in counter_mode_msgs:
    print("[")
    for val in out:
        print_scalar_slice(val[0])
    print("]")
    print(",")
print("];")

print("pub(crate) const ERIS_COUNTER_MODE_KEY: [Fp; 4] = ")
print("[")
for val in counter_mode_key:
    print_scalar_slice(val[0])
print("]")
print(";")

print("pub(crate) const ERIS_COUNTER_MODE_OUT: [[Fp; 4]; 4] = [")
for out in counter_mode_out:
    print("[")
    for val in out:
        print_scalar_slice(val[0])
    print("]")
    print(",")
print("];")
