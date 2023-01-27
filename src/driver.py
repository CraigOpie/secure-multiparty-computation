#!/usr/bin/env python3
from partymember import PartyMember

if __name__ == '__main__':
    Alice = PartyMember(6, "Alice")
    Bob = PartyMember(1, "Bob")

    ea = Alice.get_pub_key()
    step_2 = Bob.step_1(ea)
    Alice_p, Alice_zuf = Alice.step_3(step_2)

    answer = Bob.step_6(Alice_p, Alice_zuf)
    print(answer)