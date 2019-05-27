from openVulnQuery import query_client
import csv
import sys,os
import datetime
import json
from webexteamssdk import WebexTeamsAPI


api_id = None
api_secret = None
webex_token = None
webex_room_id = None 
webex_api = None

class Advisory():

    def __init__(self,advisory):
     
     self.advisory_title = advisory.advisory_title
     self.severity = advisory.sir
     self.summary = advisory.summary
     self.cvss_base_score = advisory.cvss_base_score
     self.all_product_names = advisory.product_names
     self.cvrfUrl = advisory.cvrfUrl
     self.first_published = advisory.first_published
     self.last_updated = advisory.last_updated
     self.bug_ids = advisory.bug_ids
     self.workaround = None
     self.fix = None
     self.bug_ids = None
     self.concerned_products = [] 

    def firewall_only(self): #clean product array for Cisco Firewalls 
        for p in self.all_product_names:
            if p.find("Firepower") !=-1 or p.find("Adaptive Security Appliance") != -1  or p.find("ASA") != -1 or p.find("FX-OS") != -1 or p.find("fx-os")!=-1 :
              self.concerned_products.append(p) 

    def fxos_only(self):
        for p in self.all_product_names:
            if p.find("FX-OS") == -1:
              print "test"



    def ise_only(self): #clean product array for Cisco ISE
        for p in self.all_product_names:
            if p.find("Identity Services Engine") == -1:
              print "test"

def get_report(advisories):
         
         with open('psirt.csv','w') as f:
             fieldnames = ['First_Published','Advisory','Severity','Summary','Product Names','cvss_base_score']
             writer = csv.DictWriter(f,fieldnames=fieldnames)
             writer.writeheader()
             for a in advisories:
                 dict = {'First_Published':a.first_published,
                         'Advisory':a.advisory_title,
                         'Severity':a.severity,
                         'Summary':a.summary,
                         'Product Names':a.concerned_products,
                         'cvss_base_score':a.cvss_base_score }

                 writer.writerow(dict)

         

def get_firewall_advisories():

    q_client = query_client.OpenVulnQueryClient(client_id=api_id,client_secret=api_secret)

    advisory = q_client.get_by_product('default','asa')
    firewall_advisories = []
    for a in advisory:
        adv_obj = Advisory(a)
        adv_obj.firewall_only()
        firewall_advisories.append(adv_obj)

    print "getting report"
    get_report(firewall_advisories)

    webex_api.messages.create(roomId=webex_room_id,
                            markdown= "Firewall PSIRT alert")
    file_list = ["psirt.csv"]
    webex_api.messages.create(roomId=webex_room_id,
                     files = file_list )


def get_ise_advisories():
    query_client =query_client.OpenVulnQueryClient(client_id=api_id,client_secret=api_secret)


    ise_advisory = query_client.get_by_product('default','Identity Services Engine')
    ise_advisories = []
    for a in advisory:
        adv_obj = Advisory(a)
        adv_obj.ise_only()
        ise_advisories.append(adv_obj)
    get_report(ise_advisories)

    api.messages.create(roomId=webex_room_id,
                      markdown= "ISE PSIRT alert")

    api.messages.create(roomId=webex_room_id,
                     files = "psirt.csv")



def get_fxos_advisories():

    query_client =query_client.OpenVulnQueryClient(client_id=api_id,client_secret=api_secret)

    fxos_advisory = query_client.get_by_product('default','fxos')
    fxos_advisories = []
    for a in fxos_advisory:
        adv_obj = Advisory(a)
        adv_obj.fxos_only()
        fxos_advisories.append(adv_obj)
    get_report(fxos_advisories)

    api.messages.create(roomId=webex_room_id,
                      markdown= "FXOS PSIRT alert")

    api.messages.create(roomId=webex_room_id,
                     files = "psirt.csv")
    


if __name__=='__main__':

    api_id = raw_input("Please enter your api client_id")
    api_secret = raw_input("Please enter your api client secret")

    webex_token = raw_input("Please enter your webex access_token")
    webex_room_id = raw_input("Please enter your webex room_id")

    webex_api = WebexTeamsAPI(access_token=webex_token)
    

    get_firewall_advisories()
    #get_ise_advisories()
    #get_fxos_advisories()
