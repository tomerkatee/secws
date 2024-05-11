import sys
import re
import json


def main():
    strs = scrape_responses(sys.argv[1])
    print(len(strs))

def scrape_responses(filename): 
    res = []

    with open(filename, 'r') as file:
        fields = json.load(file)
        entries = fields["log"]["entries"]
        for e in entries:
            response = e["response"]
            for h in response["headers"]:
                res.append(h["name"])
                res.append(h["value"])

            res.append(response["redirectURL"])
            
            content = response["content"]
            if "text" in content:
                res.append(content["text"])
            if "mimeType" in content:
                res.append(content["mimeType"])

        return res

if __name__ == "__main__":
    main()
