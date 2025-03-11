---
title: SOC Automation Project - Part 2
date: 2025-03-10 10:40:00 -0800
categories: [Home lab, SOC Automation Project]
tags: [cybersecurity, siem, soar, windows, sysmon, splunk, thehive, wazuh, shuffle, virustotal, home lab, virtualbox]
image: assets/img/soc_automation-project/SOC-Automation-Project-banner-2.png
description: SOC automation with Wazuh, TheHive and Shuffle - Part 2
---

## 2. Generating Telemetry and Detecting Mimikatz
### 2.1 Generating Mimikatz Events 

#### Configure occess.conf file
When we install Wazuh, the main configuration file is `occess.conf`. On Windows agent, this file is located at `Program Files (x86)\ossec-agent\occess.conf`. It is recommended to back up this file before making changes to it. A configuration error may prevent Wazuh services from starting up. 

After backing up `occess.conf`, open it by Notepad with Administrator permission. Then we scroll down and looking for `<!--log analysis-->` tag and modify the first `<localfile>` tag become:
```xml
<localfile>
    <location> Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>
```
We also remove the `<localfile>` tag with the `<location>` tag value is **Security**. Then we save the file and restart Wazuh by go to services, right click Wazuh and restart. To check if our configuration is correct, go to Wazuh dashboard, under events, make sure we in alerts index and we can search for `sysmon`.

![wazuh-manager-sysmon-search](assets/img/soc_automation-project/wazuh-manager-sysmon-search.jpg){:.post-image-80 style="border-radius: 8px;"}

#### Download and execute Mimikatz
Before downloading Mimikatz, we need to exclude the download path. To do that, open Windows Security, click on **dismiss** under **Virus & threat protection**, then double click on **Virus & threat protection**, seclect **Add or remove exclusions**, then Add an exclusion and choose Folder, then select **Download** folder.

![win10-exclude-download-folder](assets/img/soc_automation-project/win10-exclude-download-folder.jpg){:.post-image-80 style="border-radius: 8px;"}

We also need to turn off the protection in our browser.
- For **Microsoft Edge**: open browser settings, navigate to **Privacy, search, and services**, and then under **Services**, toggle the **Microsoft Defender SmartScreen** option to off.
- For **Google Chrome**: go to **Setting**, then **Privacy and security**, **Security**, select **No protection**

To download Mimikatz, we go to [Mimikatz repository](https://github.com/gentilkiwi/mimikatz/releases), and download file `mimikatz_trunk.zip`

![win10-download-mimikatz](assets/img/soc_automation-project/win10-download-mimikatz.jpg){:.post-image-80 style="border-radius: 8px;"}


Next, on Windows 10 machine, go to folder **Downloads**, **extract all** file `mimikatz_trunk.zip`. Then, we open **Power Shell** as Administrator, change directory to mimikatz folder and execute `mimikatz.exe`.


  ![](assets/img/soc_automation-project/win10-run-mimikatz.jpg){:.post-image-80 style="border-radius: 8px;"}


To make sure **Sysmon** is capturing Mimikatz, we open **Event Viewer** and navigate to **Applications and Services Logs/Microsoft/Windows/Sysmon/Operational**. We Look for `Event ID 1`, which indicates process creation.


  ![](assets/img/soc_automation-project/win10-eventviewer-mimikatz.jpg){:.post-image-80 style="border-radius: 8px;"}


At this time, we can head back to **Wazuh Manager** dashboard and search for `mimikatz` under `wazuh-archives-*` index. We can see we got two events, one with the event **ID 1** and the other one has event **ID 7**.


  ![](assets/img/soc_automation-project/wazuh-manager-search-mimikatz.jpg){:.post-image-80 style="border-radius: 8px;"}


Next we expand the event witht the event **ID 1** and take a look at the fields. We have a field called `OriginalFileName`. We will use this field to craft our alerts because if we use other fields such as `image`, the attacker can be simply rename mimikatz to anything else to bypass the alert


  ![](assets/img/soc_automation-project/wazuh-manager-expand-fields.jpg){:.post-image-80 style="border-radius: 8px;"}


#### 2.2 Creating a Custom Alert Rule 
At dashboard home page, click to the dropdown menu next to the Wazuh icon, select **Management**, **Rules**, **manage rules files**. Because we are interested specifically in the event ID 1 for sysmon, we are going find for it, put `sysmon` in the search bar and we see file `0800-sysmon_id_1.xml`, click the icon view to view the content of this file. 

We copy a rule to use to custom. We back to the rules file page and click on **Custom rules** button on the right hand side. We see `local_rules.xml` file here. Click on the pencil icon to edit it. Paste the rule we copy to this local rules file and custom it as following:
```xml
<rule id="100002" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Usage Detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
```
Once we've saved the `local_rules.xml` file, confirm the restart of the Wazuh manager to apply the new rule. To test this, try renaming the Mimikatz executable to something less conspicuous, for example, I rename `mimikatz.exe` to `goodjob.exe`. Then, we execute this renamed file and observe the Wazuh dashboard. 

Despite the name change, Wazuh will still generate an alert, demonstrating its ability to identify Mimikatz based on its original file name, even if an attacker attempts to disguise it.


  ![](assets/img/soc_automation-project/wazuh-manager-goodjob.jpg){:.post-image-80 style="border-radius: 8px;"}


## 3. Automating Response Actions
### 3.1 Integrating with VirusTotal
To further enrich our analysis of detected Mimikatz events, we'll integrate VirusTotal into our Shuffle workflow. VirusTotal analyzes files and URLs to detect malware and provides valuable information about their reputation.  
#### 3.1.1 Extract Hashes from Wazuh Events
In our Shuffle workflow, click on the **Change Me** node that follows the **Wazuh Alerts** webhook and put configuration as followings:
- **Name**: SHA256-Regex
- **Find Actions**: Regex capture group
- **Input data**: `$exec.text.win.eventdata.hashes`. we choose this value by click on the plus icon, Execution Argument then looking for hashes
- **Regex**: SHA256=([a-fA-F0-9]{64}). This regular expression will specifically capture the SHA256 hash.
 
#### 3.1.2 Add VirusTotal Node
Drag and drop the **VirusTotal v3** app node into your workflow. Then, connect it after the **SHA256-Regex** node. Configure the VirusTotal node with the following options:
- **Name**: VirusTotal
- **Find Actions**: Get a file report
- **Id**: `$extract_hashes.group_0#` (Don't forget the # at the end)

#### 3.1.3 VirusTotal Authentication
Navigate to VirusTotal website, login and get the **API key**


  ![](assets/img/soc_automation-project/virustotal-api-key.jpg){:.post-image-80 style="border-radius: 8px;"}


In our Shuffle workflow, click on **Authentication for the VirusTotal** node, paste our API key and submit. Now, whenever an alert is triggered, Shuffle will extract the SHA256 hash of the detected file and send it to VirusTotal for analysis. The results from VirusTotal will be included in the workflow data, providing valuable context for incident response. We specially focus on the attribute call last_analysis_stats which give us the important information about the hash.


  ![](assets/img/soc_automation-project/virustotal-last-analysis-stats.jpg){:.post-image-80 style="border-radius: 8px;"}


### 3.2 Sending Alerts to TheHive
To centralize our incident response and allow for collaborative investigation, we'll configure our Shuffle workflow to automatically create alerts in TheHive.

#### 3.2.1 Prepare TheHive
Log in to TheHive using the default credentials: **admin@thehive.local:secret**. Then, create a new organization.
Within the organization, create two users. I my case, I create:
- **martin** | martin@test.com | Type: Normal | Profile: Analyst , for manual interaction with TheHive.
- **SOAR** | shuffle@test.com | Type: Service | Profile: Analyst, for Shuffle integration.


  ![](assets/img/soc_automation-project/thehive-create-users.jpg){:.post-image-80 style="border-radius: 8px;"}


Then, we create password for user martin and put the API key for user SOAR, when we see the API key, we should save it because we will use it to authenticate with Shuffle

#### 3.2.2 Add TheHive Node to Shuffle
In our Shuffle workflow, drag and drop the **TheHive app** node into the workspace and connect it after the VirusTotal node. Configure the TheHive node with the following:
- **Name**: TheHive_1
- **Find Actions**: Create alert
Then, click on **Authentication for TheHive** and put the parameters which the apikey we got from user SOAR at previous step and The url is TheHive public IP address go along with port 9000. 


![](assets/img/soc_automation-project/thehive-authentication.jpg){:.post-image-50 style="border-radius: 8px;"}


We also put some parameter for TheHive


  ![](assets/img/soc_automation-project/shuffle-thehive-config.jpg){:.post-image-50 style="border-radius: 8px;"}


We need to allow TCP traffic inbound on port 9000. Therefore, go to the Firewall configution in DigitalOcean and add the **Inbound Rule** as following:


  ![](assets/img/soc_automation-project/digital-ocean-add-rule-firewall.jpg){:.post-image-80 style="border-radius: 8px;"}


With this configuration, whenever an alert is triggered in Wazuh and processed through Shuffle, a corresponding alert will be automatically created in TheHive. This allows analysts to efficiently manage, track, and investigate potential security incidents in a centralized platform.

### 3.3 Email Notifications
To ensure timely awareness of potential security incidents, we'll configure email notifications in our Shuffle workflow. This will alert the SOC analyst whenever Mimikatz is detected.

#### 3.3.1 Add Email Node:
In your Shuffle workflow, drag and drop the **Email** node into the workspace and connect it after the Virustotal node. 


  ![](assets/img/soc_automation-project/shuffle-add-email.jpg){:.post-image-80 style="border-radius: 8px;"}


Configure Email Node:
- **Name**: Send_email_notification
- **Find Actions**: Send email shuffle
- **Recipients**: [email address of SOC analyst]
- **Subject**: Mimikatz Detected!
- **Body**: 
```
Title: $exec.title
Time: $exec.text.win.eventdata.utcTime
Host: $exec.text.win.system.computer
```

  ![](assets/img/soc_automation-project/shuffle-email.jpg){:.post-image-50 style="border-radius: 8px;"}


With this configuration, an email notification will be sent to the designated SOC analyst whenever the workflow detects Mimikatz execution. This allows for immediate awareness and prompt response to potential threats. Now, we save the workflow and re run, then we go to our enail, and we will see the email from **shuffle.io**


  ![](assets/img/soc_automation-project/squarex-email.jpg){:.post-image-80 style="border-radius: 8px;"}


## 4. Conclusion
This project successfully demonstrates the construction of an automated SOC environment capable of detecting and responding to the execution of Mimikatz. By integrating Wazuh, Sysmon, TheHive, Shuffle, and VirusTotal, we've created a system that can effectively monitor for, analyze, and respond to security events.

This project provides a foundation for building more complex and robust SOC automation workflows. Potential next steps include:
- Expanding detection capabilities: Incorporate additional rules and techniques to detect other malicious activities and attacker tools.
- Enhancing response actions: Automate more sophisticated response actions, such as isolating infected machines or blocking malicious network traffic.
- Integrating with threat intelligence platforms: Leverage threat intelligence to proactively identify and mitigate emerging threats.
- Implementing continuous monitoring and improvement: Regularly review and update the SOC environment to ensure its effectiveness against evolving threats.

By building and experimenting with this homelab project, you've gained valuable hands-on experience with essential security tools and concepts. This knowledge can be applied to real-world SOC environments to improve security posture and incident response capabilities.
