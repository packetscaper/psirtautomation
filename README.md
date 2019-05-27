# Automating PSIRT notification and reports



## Overview

This project aims to use Cisco openVulnAPI utility to automatically generate reports about PSIRTs affecting various Cisco projects and notify via WebexTeams


### Prerequisites

CiscoPSIRT/openVulnAPI



```
pip install openVulnQuery

```

Webex Teams SDK

```

pip install webexteamssdk

```

CCO Account to generate PSIRT API keys

https://apiconsole.cisco.com/



### Docker Container

The script can be easily run in a container. 
Pull the container from Docker Hub with

```

docker pull packetscaper/psirtautomation


```

Run the docker in an interactive mode to allow input of api and webex keys


```

docker run -ti psirtautomation

```

