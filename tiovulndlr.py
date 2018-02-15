#!/usr/bin/python

#
# Author: James Stewart Smith
# Date:   Feb 14, 2018
#

import sys
import time
import datetime
from datetime import timedelta
from pymongo import MongoClient
import pprint
from tenable_io.api.models import Folder
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
from tenable_io.api.models import AssetList, AssetInfo, VulnerabilityList, VulnerabilityOutputList
import json
import re
import csv
import smtplib
import socket


#Download the customers (yes, this works with multiple Tenable.io customers) and work on each one.
def downloadVulns(db,configdata):
    print("Looking for customers")
    customers=db.customers
    for i in customers.find():
        print("Customer info",i)
        print("Customer Name:",i['name'])
        #See if we can make a connection to Tenable.io for this customer
        if( downloadVulnsFromTio('output.nessus',i) ):
            #If everything was successful then parse the CSV
            parseCSVIntoMongo('output.nessus',i,db)
            findRemediations(i,db,configdata)
            findNewVulns(i,db,configdata)


#This function queries all the documents in the vulns collection to find the new ones
def findNewVulns(cust,db,configdata):
    # Create a DB handle to the vulns collection
    vulns = db.vulns

    #Loop through all the vulnerabilities, grouped by the last time they were refreshed.
    for i in vulns.find({"new": {"$exists": True},"customer_id": cust['_id']}):
        print("New vuln!!! Customer ID/Asset/Protocol,Port/Plugin/CVSS:", cust['_id'],i['asset'], "/", i['protocol'], "/", i['port'], "/", i['plugin'],"/", i['cvss'])
        if float(i['cvss']) >= float(cust['cvssalertthreshold']):
            print("The vulnerability meets or exceeds the alert threshold, so sending email and syslog alerts")
            #Since the alert threshold has been reached, try sending an email and syslog.
            if sendVulnerabilityEmail(cust,i,configdata) and sendVulnerabilitySyslog(cust,i,configdata):
                #Both functions worked without error, so the vulnerability can be unflagged as new.
                print("Unflagging the vulnerability as new")
                vulns.update({"customer_id": cust['_id'], "asset": i['asset'], "protocol": i['protocol'], "port": i['port'], "plugin": i['plugin']}, {"$unset": {"new": ""}})
        else:
            #Since the alert threshold was not reached, this vulnerability can be unflagged as new.
            print("Unflagging the vulnerability as new")
            vulns.update({"customer_id": cust['_id'], "asset": i['asset'], "protocol": i['protocol'], "port": i['port'], "plugin": i['plugin']}, {"$unset": {"new": ""}})


#Send an email regarding this vulnerability.  If there is a failure it returns False, otherwise True.
def sendVulnerabilityEmail(cust,vulndata,configdata):
    print("Sending email for this vulnerability to server",configdata['smtpServer'])
    sys.stdout.flush()
    if cust['alertemail'] == "":
        print("No alert email specified, so not sending email")
        sys.stdout.flush()
        return(True)
    fromaddr=cust['alertemail']
    toaddr=cust['alertemail']
    msg=("From: %s\r\nTo: %s\r\n\r\nVulnerability found on %s/%s of asset ID %s. Plugin ID: %s. CVSS: %s" % (fromaddr, toaddr,vulndata['protocol'],vulndata['port'],vulndata['asset'],vulndata['plugin'],vulndata['cvss']))

    print("Email msg:",msg)
    print("Attempting connection to email server",configdata['smtpServer'],"on port",configdata['smtpPort'])
    sys.stdout.flush()

    try:
        server = smtplib.SMTP(configdata['smtpServer'],configdata['smtpPort'])
    except:
        print("Unable to connect to SMTP server:",sys.exc_info()[0])
        sys.stdout.flush()
        return(False)

    if configdata['smtpSecure']:
        print("Making email link secure")
        sys.stdout.flush()
        server.starttls()
        if configdata['smtpUsername'] != "":
            print("Logging into SMTP server")
            sys.stdout.flush()
            try:
                server.login(configdata['smtpUsername'],configdata['smtpPassword'])
            except:
                print("Unable to log into SMTP server:",sys.exc_info()[0])
                sys.stdout.flush()
                return(False)

    print("Sendmail email message")
    sys.stdout.flush()
    try:
        server.sendmail(fromaddr, toaddr, msg)
    except:
        print("Unable to send email:", sys.exc_info()[0])
        sys.stdout.flush()
        return (False)

    print("Closing email connection")
    sys.stdout.flush()
    server.quit()
    return(True)

#Send a syslog regarding this vulnerability.  If there is a failure then return False, otherwise return True
def sendVulnerabilitySyslog(cust,vulndata,configdata):
    if cust['syslogserver'] == "":
        print("No syslog server specified, so not sending syslog message")
        return(True)
    print("Sending syslog for this vulnerability to",cust['syslogserver'])
    msg=("<%d>Vulnerability found on %s/%s of asset ID %s. Plugin ID: %s. CVSS: %s" % (129,vulndata['protocol'],vulndata['port'],vulndata['asset'],vulndata['plugin'],vulndata['cvss']))

    print("Syslog msg:",msg)
    #TODO - send syslog over network
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except:
        print("Unable to open socket:", sys.exc_info()[0])
        sys.stdout.flush()
        return (False)
    try:
        s.sendto(bytearray(msg,"utf-8"), (cust['syslogserver'], 514))
    except:
        print("Unable to send syslog message:", sys.exc_info()[0])
        sys.stdout.flush()
        return (False)
    s.close()

    return(True)




#This function queries all the documents in the vulns collection to find those that have been remediated
def findRemediations(cust,db,configdata):
    # Create a DB handle to the vulns collection
    vulns = db.vulns
    remediated = db.remediated

    #Set a counter
    c=0
    #Loop through all the vulnerabilities, grouped by the last time they were refreshed.
    for i in vulns.aggregate([{"$match": {"customer_id": cust['_id']}},{"$group": {"_id": "$lastrefresh", "count": {"$sum": 1}}},{"$sort": {"_id": -1}}]):
        #If there are more rows than the first one, these indicate vulnerabilities that have been remediated.
        if c > 0:
            print("Some vulnerabilities have been remediated.  Last refresh/count:",i['_id'],"/",i['count'])
            for j in vulns.find({"lastrefresh": i['_id']}):
                print("Remediated vuln!!! Customer ID/Asset/Protocol,Port/Plugin/CVSS:",cust['_id'],"/", j['asset'], "/", j['protocol'], "/", j['port'], "/",j['plugin'], "/", j['cvss'])
        c=c+1
#TODO - remove the remediated vulnerability from the vulns table.  Maybe put in some workflow to send a syslog or email.


#Parse the CSV file and put into Mongo DB
def parseCSVIntoMongo(filename,cust,db):
    #Create a DB handle to the vulns collection
    vulns=db.vulns

    currenttime=datetime.datetime.utcnow()
    #Open the file
    with open(filename, "r") as csvfile:
        #Have the file contents treated as a CSV
        vulnreader=csv.DictReader(csvfile)

        #Loop through each of the rows and write it to the Mongo DB
        for row in vulnreader:
            #Create an empty vulndata variable
            vulndata={}
            print("Asset/Protocol,Port/Plugin:",row['Asset UUID'],"/",row['Protocol'],"/",row['Port'],"/",row['Plugin ID'])
            sys.stdout.flush()

            vulns.update({"customer_id": cust['_id'], "asset": row['Asset UUID'], "protocol": row['Protocol'], "port": row['Port'], "plugin": row['Plugin ID']}, {"$set":{"customer_id": cust['_id'], "asset": row['Asset UUID'], "protocol": row['Protocol'], "port": row['Port'], "plugin": row['Plugin ID'], "cvss": row['CVSS'], "lastrefresh": currenttime}, "$setOnInsert": {"new": currenttime}}, upsert=True)





#Download the CSV file of vulnerabilities for a particular customer.
def downloadVulnsFromTio(filename,cust):
    DEBUG = True

    #Open the connection to Tio  for the particular customer
    print("Connecting to Tenable.io for:",cust['name'])
    try:
        tioconn = TenableIOClient(access_key=cust['_id'], secret_key=cust['secretkey'])
    except:
        print("Problem connecting to Tenable.io")
        return(False)

    #Download a CSV file

    # Make the request for the file.
    requesturl = "workbenches/export?format=csv&report=vulnerabilities&chapter=vuln_by_plugin&date_range=0"
    resp = tioconn.get(requesturl)

    if DEBUG:
        print("Raw response text:", resp.text)
    respdata = json.loads(resp.text)

    downloadid = ""
    try:
        downloadid = str(respdata['file'])
    except:
        print("Unable to start download")
        return (False)

    statusurl = "workbenches/export/" + downloadid + "/status"
    downloadurl = "workbenches/export/" + downloadid + "/download"

    if DEBUG:
        print("Waiting for download ID", downloadid)
        print("status URL  :", statusurl)

    downloadstatus = ""
    while (downloadstatus != "ready"):
        resp = tioconn.get(statusurl)
        respdata = json.loads(resp.text)
        downloadstatus = respdata['status']
        if DEBUG:
            print("Raw response", resp.text)
        time.sleep(2)

    resp = tioconn.get(downloadurl)
    if DEBUG:
        print("Raw response", resp)
    with open(filename, 'wb') as fp:
        for chunk in resp.text:
            fp.write(chunk.encode('utf-8'))
    fp.close()
    sys.stdout.flush()
    return(True)




#############################################
###
### START OF PROGRAM
###
#############################################
print("Starting Tenable.io Vulnerability Downloader")


#Read configuration file
with open('./configuration/config.json',"r") as jsonfile:
    jsondata=jsonfile.read()
configdata=json.loads(jsondata)

print("Using email server",configdata['smtpServer'])

#Make the connection to the Mongo DB, which assumes an inter-container connection
print("Connecting to Mongo:",configdata['mongoConnectionString'])
client=MongoClient(configdata['mongoConnectionString'])

print("Connecting to database")
db=client.tiovulndb

#Assumes there is a customers collection in the tiovulndb
print("Selecting a collection")
customers=db.customers

print("About to enter main loop")

sys.stdout.flush()

loop=True
while loop:
    starttime=datetime.datetime.utcnow()
    print("Start of main loop")
    print("Downloading Vulnerabilities")
    #TODO - check if there were any scans run since the last update.  If not, then maybe not check as often.
    downloadVulns(db,configdata)
    print("Elapsed time for this loop:",(datetime.datetime.utcnow()-starttime))
    print("Sleeping for",configdata['updateInterval'],"seconds")
    sys.stdout.flush()
    time.sleep(configdata['updateInterval'])
