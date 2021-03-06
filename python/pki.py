# Copyright (C) 2016 Teledildonics group

f=file('mojo_upgrade.txt')
j=f.readlines()
reciprocal_map = {}
i = 0
while i < len(j):
    if j[i][0] != '#' and j[i].strip() != '':
        a=j[i].strip()
        b=j[i+1].strip()
        reciprocal_map[a] = b
        reciprocal_map[b] = a
        i += 1
    i += 1

from nacl.hash import sha256
from nacl import bindings as c

def init(prefs, the_ephemeral_key, has=False):
    encrypted_prefs = []
    for pref in prefs:
        if not has:
            hashed_reciprocal_pref = sha256(reciprocal_map[pref])
            want_pref = c.crypto_scalarmult(the_ephemeral_key, hashed_reciprocal_pref)
            encrypted_prefs.append(want_pref)
        else:
            hashed_pref = sha256(pref)
            have_pref = c.crypto_scalarmult(the_ephemeral_key, hashed_pref)
            encrypted_prefs.append(have_pref)
    return encrypted_prefs

def compare(set_a, set_b, own):
    conclusions = []
    for i in range(0,len(set_a)):
        a = set_a[i]
        if a in set_b:
            conclusions.append(("I like '" + own[i] + "' and they like '" + reciprocal_map[own[i]]) + "'")
    return conclusions

import nacl.utils
def alice(network):
    # Alice sends her wants
    alices_prefs = map(lambda x: x.strip(), file("alice.txt").readlines())
    alices_ephemeral_key = nacl.utils.random(32)
    alices_encrypted_wants = init(alices_prefs, alices_ephemeral_key, False)
    # negotiate set size
    alices_prefs_count = len(alices_prefs)
    network.send(alices_prefs_count)
    bobs_prefs_count = network.recv()
    if alices_prefs_count > bobs_prefs_count:
        alices_prefs_count = bobs_prefs_count
    # compare prefs
    bobs_encrypted_haves = []
    for i in range(0, alices_prefs_count):
        # send Alice's point
        network.send(alices_encrypted_wants[i])
        # get it back encrypted
        alices_encrypted_wants[i] = network.recv()
        # get Bob's point and encrypt it
        bobs_encrypted_have = c.crypto_scalarmult(alices_ephemeral_key, network.recv())
        if bobs_encrypted_have in bobs_encrypted_haves:
            print "Alice feels somebody is cheating"
            return
        bobs_encrypted_haves.append(bobs_encrypted_have)
        # test if we are still interested
        if len(set.intersection(set(bobs_encrypted_haves), set(alices_encrypted_wants))) < i/10:
            print "Alice feels like this is going nowhere"
        network.send(bobs_encrypted_haves[-1])
    for i in compare(alices_encrypted_wants, bobs_encrypted_haves, alices_prefs):
        print "Alice learned:", i

def bob(network):
    # Bob sends his haves
    bobs_prefs = map(lambda x: x.strip(), file("bob.txt").readlines())
    bobs_ephemeral_key = nacl.utils.random(32)
    bobs_encrypted_haves = init(bobs_prefs, bobs_ephemeral_key, True)
    # negotiate set size
    bobs_prefs_count = len(bobs_prefs)
    alices_prefs_count = network.recv()
    if bobs_prefs_count > alices_prefs_count:
        bobs_prefs_count = alices_prefs_count
    network.send(bobs_prefs_count)
    # compare prefs
    alices_encrypted_wants = []
    for i in range(0, bobs_prefs_count):
        # receive Alice's point and encrypt it
        alices_encrypted_want = c.crypto_scalarmult(bobs_ephemeral_key, network.recv())
        if alices_encrypted_want in alices_encrypted_wants:
            print "Bob feels somebody is cheating"
            return
        alices_encrypted_wants.append(alices_encrypted_want)
        # test if we are still interested
        if len(set.intersection(set(bobs_encrypted_haves), set(alices_encrypted_wants))) < i/10:
            print "Bob feels like this is going nowhere"
        # send encrypted point back
        network.send(alices_encrypted_wants[-1])
        # send bobs point
        network.send(bobs_encrypted_haves[i])
        # get it back encrypted
        bobs_encrypted_haves[i] = network.recv()
    for i in compare(bobs_encrypted_haves, alices_encrypted_wants, bobs_prefs):
        print "Bob learned:", i

from multiprocessing import Process, Pipe

network_ab, network_ba = Pipe()

b=Process(target=bob, args=(network_ba,))
a=Process(target=alice, args=(network_ab,))
a.start()
b.start()
a.join()
b.join()
