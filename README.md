[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/packetscaper/psirtautomation)
# Automating PSIRT notification and reports

## Introduction

Cisco PSIRT global team manages the receipt, investigtion, and public reporting of security vulnerability information that is related 
to Cisco product and networks.
The PSIRTs are published in the below link.

The Cisco PSIRT openVuln API is a RESTful API that allows customers to obtain Cisco security vulnerability information in different machine-consumable formats supporting industrywide standards.
More information can be found in the below page.

https://github.com/CiscoPSIRT/openVulnAPI


## Overview

Timely notification of such PSIRTs to the concerned stake holders once PSIRTs are public is essential for compliance and auditing purposes.
This project aims to use Cisco openVulnAPI utility to automatically generate daily reports about PSIRTs affecting various Cisco projects and notify via WebexTeams. 
Currently it does daily checks for PSIRTs released for ISE,ASA and Firepower.


### Prerequisites

CiscoPSIRT/openVulnAPI



```
pip install openVulnQuery

```

Webex Teams SDK

```

pip install webexteamssdk

```


### Setup

1. Use your CCO Account to generate an api client id and an api client secret using the below link <br>
   https://apiconsole.cisco.com/ <br>
   These keys will be used for calling API calls using openVulnApi

2. Webex Teams <br>
  i.   Create a webex space from your webex teams app <br>
  ii.  Get the webex room id from the below link by logging in your account <br>
       https://developer.webex.com/docs/api/v1/rooms/list-rooms <br>
  iii. Create a new bot from the below link <br>
       https://developer.webex.com/my-apps/new/bot <br>
       Note the access token of the bot <br>
  iv.  Add the bot to the new webex space created
  v.   Add more users to the same webex space if required.


### Docker Container

The script can be easily run in a container. 
Pull the container from Docker Hub with

```

docker pull packetscaper/psirtautomation


```

Run the docker in an interactive mode to allow input of api and webex keys


```

docker run -ti packetscaper/psirtautomation

```


## Example 
```
#python psirts.py 
Please enter your api client_id 
eqr8mzrk78m8 
Please enter your api client secret 
FbE8XteaMgX 
Please enter your webex access_token 
NzZlMzgwYzQt 
Please enter your webex room_id 
Y2lzY29zcGF 
running script in the background 
```
