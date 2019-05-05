import sys,os
import datetime
import json
import csv


def psirt_notification(): #checks every day to see if any new PSIRTs announced
    today = datetime.date.today()

    print "getting daily"
    #openVulnQuery --config credentials.json --first_published 2019-04-17:2019-04-17 --all
    #command = "openVulnQuery --config credentials.json --first_published " + str(today) + ":" + str(
    #           today) + "--all --json current2.json"
    command = "openVulnQuery --config credentials.json --first_published 2019-04-17:2019-04-17 --all --json today_psirts.json"
    os.system(command)
    with open('today_psirts.json') as f:
     json_resp = json.load(f)
    return json_resp





def gen_report(json):
    with open('psirt_update.csv','w') as f:
     fieldnames = ['Product','Advisory','CVE','Link','CVSS_Base_Score','Severity','Bugs','Summary']
     writer = csv.DictWriter(f,fieldnames=fieldnames)
     dict_list = []
     writer.writeheader()
     for advisory in json:
        for product in advisory["product_names"]:
            dict = {'Product': product , 'Advisory':advisory["advisory_id"], 'CVE' : advisory["cves"], 'Link':advisory["publication_url"], 'CVSS_Base_Score':advisory["cvss_base_score"],
                   'Severity':advisory["sir"],'Bugs':advisory["bug_ids"], 'Summary':advisory["summary"]}
            writer.writerow(dict)
            #dict_list = dict_list.append(dict)
            #print product, advisory["advisory_id"],advisory["cves"], advisory["publication_url"], advisory["cvss_base_score"],advisory["sir"], advisory["bug_ids"], '\r' #advisory["summary"]
     #writer.writerow(dict_list)
