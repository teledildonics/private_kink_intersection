# Copyright (C) 2016 Teledildonics group

f=file('mojo_upgrade.txt')
j=f.readlines()
complement_map = {}
for i in range(0,len(j),2):
    if j[i][0] != '#' and j[i].strip() != '':
        a=j[i].strip()
        b=j[i+1].strip()
        #print a,b
        complement_map[a] = b
        complement_map[b] = a

from nacl.hash import sha256
from nacl import bindings as c

def init(prefs, the_ephemeral_key, has=False):
    encrypted_prefs = []
    for pref in prefs:
        if not has:
            hashed_complement_pref = sha256(complement_map[pref])
            want_pref = c.crypto_scalarmult(the_ephemeral_key, hashed_complement_pref)
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
            conclusions.append(("I like to " + own[i] + " and they like to " + complement_map[own[i]]))
    return conclusions

import nacl.utils
def alice(network_ab, alices_prefs_count):
    # Alice sends her wants
    alices_wants = map(lambda x: x.strip(), file("alice.txt").readlines())
    alices_prefs_count = len(alices_wants)
    alices_ephemeral_key = nacl.utils.random(16)
    alices_encrypted_wants = init(alices_wants, alices_ephemeral_key, False)
    # negotiate set size
    network_ab.send(alices_prefs_count)
    bobs_prefs_count = network_ab.recv()
    if alices_prefs_count > bobs_prefs_count:
        alices_prefs_count = bobs_prefs_count
    # compare prefs
    bobs_encrypted_haves = []
    for i in range(0, alices_prefs_count):
        # send Alice's point
        network_ab.send(alices_encrypted_wants[i])
        # get it back encrypted
        alices_encrypted_wants[i] = network_ab.recv()
        # get Bob's point and encrypt it
        bobs_encrypted_have = c.crypto_scalarmult(alices_ephemeral_key, network_ab.recv())
        if bobs_encrypted_have in bobs_encrypted_haves:
            print "Alice feels somebody is cheating"
            #return
        bobs_encrypted_haves.append(bobs_encrypted_have)
        # test if we are still interested
        if len(set.intersection(set(bobs_encrypted_haves), set(alices_encrypted_wants))) < i/10:
            print "Alice feels like this is going nowhere"
        network_ab.send(bobs_encrypted_haves[-1])
    for i in compare(alices_encrypted_wants, bobs_encrypted_haves, alices_wants):
        print "Alice learned:", i

def bob(network_ba, bobs_prefs_count):
    # Bob sends his haves
    bobs_haves = map(lambda x: x.strip(), file("bob.txt").readlines())
    bobs_ephemeral_key = nacl.utils.random(16)
    bobs_encrypted_haves = init(bobs_haves, bobs_ephemeral_key, True)
    bobs_prefs_count = len(bobs_haves)
    # negotiate set size
    alices_prefs_count = network_ba.recv()
    if bobs_prefs_count > alices_prefs_count:
        bobs_prefs_count = alices_prefs_count
    network_ba.send(bobs_prefs_count)
    # compare prefs
    alices_encrypted_wants = []
    for i in range(0, bobs_prefs_count):
        # receive Alice's point and encrypt it
        alices_encrypted_want = c.crypto_scalarmult(bobs_ephemeral_key, network_ba.recv())
        if alices_encrypted_want in alices_encrypted_wants:
            print "Bob feels somebody is cheating"
            #return
        alices_encrypted_wants.append(alices_encrypted_want)
        # test if we are still interested
        if len(set.intersection(set(bobs_encrypted_haves), set(alices_encrypted_wants))) < i/10:
            print "Bob feels like this is going nowhere"
        # send encrypted point back
        network_ba.send(alices_encrypted_wants[-1])
        # send bobs point
        network_ba.send(bobs_encrypted_haves[i])
        # get it back encrypted
        bobs_encrypted_haves[i] = network_ba.recv()
    for i in compare(bobs_encrypted_haves, alices_encrypted_wants, bobs_haves):
        print "Bob learned:", i

from multiprocessing import Process, Pipe

network_ab, network_ba = Pipe()

b=Process(target=bob, args=(network_ba,24))
a=Process(target=alice, args=(network_ab,24))
a.start()
b.start()
a.join()
b.join()
