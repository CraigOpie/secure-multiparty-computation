#!/usr/bin/env python3
from partymember import PartyMember
import sys

if __name__ == '__main__':
    Alice = PartyMember(int(sys.argv[1]), "Alice")
    Bob = PartyMember(int(sys.argv[2]), "Bob")

    ea = Alice.get_pub_key()
    step_2 = Bob.step_1(ea)
    Alice_p, Alice_zuf = Alice.step_3(step_2)

    answer = Bob.step_6(Alice_p, Alice_zuf)
    print(answer)