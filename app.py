#!venv/bin/python

import requests
import textwrap
import json
import io
from optparse import OptionParser

class Colors (object):

    GREEN = "\033[32m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    PINK = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    NORMAL = "\033[0;39m"


class Searcher (object):

    cve_url = "http://cve.circl.lu/api/cve/{cve}"
    github_url = "https://api.github.com/search/repositories?q={cve}"

    def bootstrap(self, arg_cve: str):
        for cve in arg_cve.split(','):
            buffer = []
            try:
                resp = requests.get(self.cve_url.format(cve=cve))
            except Exception as ex:
                print(str(ex))
            else:
                if resp.status_code == 200:
                    data = json.loads(resp.text)

                    cvss = data.get("cvss", None)
                    summary = data.get("summary", None)
                    exploitdb = data.get("exploit-db", None)
                    packetstorm = data.get("packetstorm", None)
                    metasploit = data.get("metasploit", None)
                    nessus = data.get("nessus", None)

                    if cvss and summary:
                        res1 = self.show_cvss(cve, cvss, summary)
                        buffer.extend(res1)

                    if exploitdb:
                        res2 = self.show_exploitdb(exploitdb)
                        buffer.extend(res2)

                    if packetstorm:
                        res3 = self.show_packetstorm(packetstorm)
                        buffer.extend(res3)

                    if metasploit:
                        res4 = self.show_metasploit(metasploit)
                        buffer.extend(res4)

                    if nessus:
                        res5 = self.show_nessus(nessus)
                        buffer.extend(res5)

            try:
                resp = requests.get(self.github_url.format(cve=cve))
            except Exception as ex:
                print(str(ex))
            else:
                if resp.status_code == 200:
                    data = json.loads(resp.text)
                    buffer.extend(self.show_github(data))

            with io.open("app.log", "a") as fh:
                fh.write("\n"*2 + "="*100 + "\n"*2)
                fh.write("\n".join(buffer))

            print("\n".join(buffer))

    def show_cvss(self, cve: str, cvss: dict, summary: dict):
        text = [
            "+" + "-" * 80 + "+",
            "| {} , CVSS {} ".format(cve, cvss),
            "+" + "-" * 80 + "+",
            "+-- Summary " + "-" * 69 + "+\n",
            "\n".join(textwrap.wrap(summary, 80)),
            "+ " + "-" * 79 + "+\n",
        ]
        return text

    def show_exploitdb(self, data:dict):
        text = [
            "",
            "+-- Exploit DB " + "-" * 66 + "+",
        ]

        for item in data:
            text.extend([
                "| Title | {}".format(item.get("title")),
                "| URL   | {}".format(item.get("source")),
                "+" + "-" * 80 + "+",
            ])
        return text

    def show_packetstorm(self, data:dict):
        text = [
            "",
            "+-- Packet Storm" + "-" * 65 + "+",
        ]
        for item in data:
            text.extend([
                "| Title | {}".format(item.get("title")),
                "| URL   | {}".format(item.get("data source")),
                "+" + "-" * 80 + "+",
            ])
        return text

    def show_metasploit(self, data: dict):
        text = [
            "",
            "+-- Metasploit " + "-" * 65 + "+",
        ]
        for item in data:
            text.extend([
                "| Title | {}".format(item.get("title")),
                "| URL   | {}".format(item.get("source")),
                "| ID    | {}".format(item.get("id")),
                "+" + "-" * 80 + "+",
            ])
        return text

    def show_github(self, data):
        text = [
            "",
            "+-- Github " + "-" * 65 + "+",
        ]
        for item in data.get("items"):
            text.extend([
                "| Repo | {}".format(item.get("full_name")),
                "| Desc | {}".format(item.get("description")),
                "| URL  | {}".format(item.get("html_url")),
                "+" + "-" * 80 + "+",
            ])
        return text

    def show_nessus(self, data: dict):
        text = [
            "",
            "+-- Nessus " + "-" * 65 + "+",
        ]
        for item in data:
            text.extend([
                "| Title  | {}".format(item.get("title")),
                "| Source | {}".format(item.get("source")),
                "+" + "-" * 80 + "+",
            ])
        return text


if __name__ == '__main__':
    
    parse = OptionParser()

    parse.add_option("-c", "--cve", dest="cve", help="CVE a buscar", type=str)

    (opts, args) = parse.parse_args()

    cve = opts.cve

    if cve:
        s = Searcher()
        s.bootstrap(cve)
    else:
        parse.print_help()
