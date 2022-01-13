import requests
import os
import json
import base64
import xml.etree.ElementTree as ET
from xml.dom import minidom

from requests.api import get

def authEncrypt(jamfAuthCerts):
    jamfAuthCertsEncode = jamfAuthCerts.encode("ascii")
    base64_bytes = base64.b64encode(jamfAuthCertsEncode)
    base64_string = base64_bytes.decode("ascii")
    return base64_string

def jamfCerts(jamfAuthCerts):
    encodedCerts = authEncrypt(jamfAuthCerts)
    return {"jamfClassic": encodedCerts,
        "jamfProToken": "xxxxxxxxxx"}

def makePatchPolicy(appName, patchName,patchID, jamfURL, headers):
    #Create a Patch Policy asociated to the patch ID
    tree = ET.parse('patchPolicy.xml')
    root = tree.getroot()
    ### Edit XML Here
    root[0][0].text = f"{patchName}"
    root[2][1].text = f"Update {appName}"
    root[2][2][2].text = f"{appName} Update Available"
    root[2][2][3].text = f"{patchName}"
    root[3].text = f"{patchID}" 

    ###
    xmlstr = ET.tostring(root, encoding='unicode', method='xml')
    print(xmlstr)
    xmlstr = xmlstr.replace("\n","")
    xmlstr = xmlstr.replace(" ","")
    print(xmlstr)
    postURL = f"{jamfURL}/JSSResource/patchpolicies/softwaretitleconfig/id/{patchID}"
    response = requests.post(url=postURL, headers=headers, data=xmlstr)
    print(f"{patchName} policy finished with status: {response.status_code}")
    return

def main():
    #----------------------- Header Setup -------------------------
    with open('config.json') as inFile:
        configData = json.load(inFile)

    requestToken = jamfCerts(configData["jamfCerts"])

    jamfUrl = configData["jamfURL"]
    getHeader = {
            'Authorization': f'Basic {requestToken["jamfClassic"]}',
            'Accept': 'application/json'
    }
    postHeader = {
            'Authorization': f'Basic {requestToken["jamfClassic"]}',
    }
    allPoliciesURL = f"{jamfUrl}/JSSResource/policies"

    #----------------------- Check if Policy was created -------------------------
    appName = input("Please enter in the application name used by the policy created(Eg. GoogleDrive, Google Chrome): ")
    appName = str(appName)

    responce = requests.get(url=allPoliciesURL, headers=getHeader)
    policyList = responce.json()
    policyNameInstall = f"Install Latest {appName}"
    policyNameTEST = f"TEST-{appName}"
    foundPolicy = False
    for policy in policyList["policies"]:
        if policyNameInstall == policy["name"]:
            policyID = policy["id"]
            print(f"Found {policyNameInstall} with policy ID of {policyID}")
            foundPolicy = True
            break
        elif policyNameTEST == policy["name"]:
            policyID = policy["id"]
            print(f"Found {policyNameTEST} with policy ID of {policyID}")
            foundPolicy = True
            break
    if foundPolicy == False:
        print(f"Cound not find policy with names: {policyNameInstall} or {policyNameTEST}\nPolicy probably not created.")
        raise SystemExit

    #----------------------- Check of Patch was Created -------------------------
    policyIDURL = f"{jamfUrl}/JSSResource/policies/id/{policyID}"

    patchName = input("Please enter in the patch name used in the patch created(Eg. GoogleDrive, Google Chrome): ")
    patchName = str(patchName)

    allPatchesURL = f"{jamfUrl}/JSSResource/patchsoftwaretitles"
    responce = requests.get(url=allPatchesURL, headers=getHeader)
    softwareTitles = responce.json()
    foundPatch = False

    for patch in softwareTitles["patch_software_titles"]:
        if patchName == patch["name"]:
            patchID = patch["id"]
            print(f"Found {patchName} with patch ID of {patchID}")
            foundPatch = True
            break
    if foundPatch == False:
        print(f"Cound not find patch with name: {patchName}\nPlease create the patch or confirm it's correct name before retrying script")
        raise SystemExit
    
    #----------------------- Find Name of the Package -------------------------
    pkgName = input("Please enter in the name of the package used in the patch created(Eg. GoogleDrive, Opera): ")
    pkgName = str(pkgName)

    #----------------------- Create Patch Policy Test and Stable ----------------
    patchPoliciesURL = f"{jamfUrl}/JSSResource/patchpolicies/softwaretitleconfig/id/{patchID}"
    print(patchPoliciesURL)
    response = requests.get(url=patchPoliciesURL, headers=getHeader)
    patchPolicies = response.json()
    print(patchPolicies)

    patchPolicyID = patchPolicies['patch policies'][0]['id']
    patchPoliciesIDURL = f"{jamfUrl}/JSSResource/patchpolicies/id/{patchPolicyID}"
    print(patchPoliciesURL)
    response = requests.get(url=patchPoliciesIDURL, headers=getHeader)
    print(response.status_code)

    testExist = False
    stableExist = False
    for policy in patchPolicies['patch policies']:
        if policy['name'] == f"{patchName} Test":
            #Test Policy Exists
            testExist = True
        elif policy['name'] == f"{patchName} Stable":
            #Stable Policy Exists
            stableExist = True
    
    if testExist != True:
        print("Creating Test Policy")
        makePatchPolicy(appName=appName, patchName=f"{patchName} Test", patchID=patchID, jamfURL=jamfUrl, headers=postHeader)
    if stableExist != True:
        print("Creating Stable Policy")
        makePatchPolicy(appName=appName, patchName=f"{patchName} Stable", patchID=patchID, jamfURL=jamfUrl, headers=postHeader)
    
    #----------------------- Create Parent Patch and Parent Prod Recipe----------------
    tree = ET.parse('patchTemp.xml')
    root = tree.getroot()
    ### Edit XML Here
    root[0][1].text = f"Move {appName} package into testing"
    root[0][3].text = f"local.ptch.{appName}.FSLead"
    root[0][9][0][1][1].text = f"Install Latest {appName}"
    root[0][9][0][1][3].text = f"{patchName}"
    root[0][9][0][1][5].text = f"{pkgName}"
    root[0][9][0][1][7].text = f"Install Latest {appName}"
    root[0][9][0][1][9].text = f"-1"

    with open(f'FSLead.{pkgName}.ptch.recipe', 'wb') as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n')
        tree.write(f, encoding='utf-8')

    tree = ET.parse('prodTemp.xml')
    root = tree.getroot()
    ### Edit XML Here
    root[0][1].text = f"Move {appName} package from testing to production"
    root[0][3].text = f"local.ptch.{appName}.FSLead"
    root[0][5][1].text = f"{pkgName}"
    root[0][9][0][1][1].text = f"{pkgName}"
    root[0][9][0][1][3].text = f"{patchName}"
    root[0][9][0][1][5].text = f"7"

    with open(f'FSLead.{pkgName}.prod.recipe', 'wb') as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n')
        tree.write(f, encoding='utf-8')
    #----------------------- Create Create Overides ----------------    

if __name__ == "__main__":
    main()