import sys
import re
import json


def main():
    strs = scrape_requests(sys.argv[1])
    print(len(strs))

def scrape_requests(filename): 
    res = []

    with open(filename, 'r') as file:
        fields = json.load(file)
        entries = fields["log"]["entries"]
        for e in entries:
            request = e["request"]
            for h in request["headers"]:
                res.append(h["name"])
                res.append(h["value"])

            for c in request["cookies"]:
                res.append(c["name"])
                res.append(c["value"])

            for a in request["queryString"]:
                res.append(a["name"])
                res.append(a["value"])

            if "postData" in request:
                postData = request["postData"]
                res.append(postData["mimeType"])
                res.append(postData["text"])

                for p in postData["params"]:
                    res.append(p["name"])
                    res.append(p["value"]) 

        return res


if __name__ == "__main__":
    main()
