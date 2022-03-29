from openVulnQuery import query_client
import csv
import sys,os
import datetime
import json
from webexteamssdk import WebexTeamsAPI
import schedule
import time 

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
            if p.find("FX-OS") !=-1 or p.find("FXOS") !=-1:
             self.concerned_products.append(p) 



    def ise_only(self): #clean product array for Cisco ISE
        for p in self.all_product_names:
            if p.find("Identity Services Engine") != -1:
             self.concerned_products.append(p) 

def get_report(advisories,product):
         today = str(datetime.date.today())
         file_name = product+today+".csv"
         with open(file_name,'w') as f:
             fieldnames = ['First_Published','Advisory','Severity','Summary','Product Names','cvss_base_score']
             writer = csv.DictWriter(f,fieldnames=fieldnames)
             writer.writeheader()
             advisory_flag = 0
             for a in advisories:
                 if a.first_published.find(today) != -1:
                  advisory_flag = 1
                  dict = {'First_Published':a.first_published,
                         'Advisory':a.advisory_title,
                         'Severity':a.severity,
                         'Summary':a.summary,
                         'Product Names':a.concerned_products,
                         'cvss_base_score':a.cvss_base_score }

                  writer.writerow(dict)

         return advisory_flag      
         

def get_firewall_advisories():
    today = str(datetime.date.today())
    q_client = query_client.OpenVulnQueryClient(client_id=api_id,client_secret=api_secret)

    firewall_advisory = q_client.get_by_product('default','asa')
    firewall_advisories = []
    for a in firewall_advisory:
        adv_obj = Advisory(a)
        adv_obj.firewall_only()
        firewall_advisories.append(adv_obj)

    print("getting report")
    if (get_report(firewall_advisories,"firewall") == 1):

     webex_api.messages.create(roomId=str(webex_room_id),
                            markdown= "Firewall PSIRT alert for " + today )
     file_list = ["firewall"+today+".csv"]
     webex_api.messages.create(roomId=str(webex_room_id),
                     files = file_list )
    else:
        webex_api.messages.create(roomId=str(webex_room_id),
                            markdown= "No Firewall PSIRT announced today ")


def get_ise_advisories():
    today = str(datetime.date.today())
    q_client =query_client.OpenVulnQueryClient(client_id=api_id,client_secret=api_secret)


    ise_advisory = q_client.get_by_product('default','Identity Services Engine')
    ise_advisories = []
    for a in ise_advisory:
        adv_obj = Advisory(a)
        adv_obj.ise_only()
        ise_advisories.append(adv_obj)
           
    if (get_report(ise_advisories,"ise")==1):


     webex_api.messages.create(roomId=str(webex_room_id),
                      markdown= "ISE PSIRT alert for " + today)
     file_list = ["ise"+today+".csv"]
     webex_api.messages.create(roomId=str(webex_room_id),
                     files = file_list )
    else :
        webex_api.messages.create(roomId=str(webex_room_id),
                        markdown= "No ISE PSIRT announced today ")



def get_fxos_advisories():
    today = str(datetime.date.today())
    q_client =query_client.OpenVulnQueryClient(client_id=api_id,client_secret=api_secret)

    fxos_advisory = q_client.get_by_product('default','fxos')
    fxos_advisories = []
    for a in fxos_advisory:
        adv_obj = Advisory(a)
        adv_obj.fxos_only()
        fxos_advisories.append(adv_obj)
    if (get_report(fxos_advisories,"fxos") ==1):

     webex_api.messages.create(roomId=str(webex_room_id),
                      markdown= "FXOS PSIRT alert for " + today )
     file_list = ["fxos"+today+".csv"]
     webex_api.messages.create(roomId=str(webex_room_id),
                     files = file_list)
    
    else :

        webex_api.messages.create(roomId=str(webex_room_id),
                        markdown= "No FXOS PSIRT announced today")


def daily_check():
  print("Checking for any new PSIRT")
  
  get_firewall_advisories()
  get_ise_advisories()
  get_fxos_advisories()


if __name__=='__main__':
    today = str(datetime.date.today())
    api_id = input("Please enter your api client_id \n")
    api_secret = input("Please enter your api client secret \n")

    webex_token = input("Please enter your webex access_token \n")
    webex_room_id = input("Please enter your webex room_id \n")
    
    pid = os.fork()
    if pid != 0:
       sys.exit()

    print(" running script in the background")
    webex_api = WebexTeamsAPI(access_token=webex_token)

    daily_check()    
    schedule.every().day.at("23:55:00").do(daily_check)

    while 1:
        schedule.run_pending()
        time.sleep(100)




