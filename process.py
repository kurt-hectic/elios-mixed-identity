import json
import csv
import re
import io
import os
import sys

import pandas as pd
import numpy as np


from datetime import date
from os import listdir
from os.path import isfile, join
from zipfile import ZipFile
from io import BytesIO

directory_web = r".\web_logs"
directory_elios_audit_logs = r".\ELIOS_audit_logs"
directory_joint_logs = r".\joint_logs"

directory_out = r".\out"

def process_web_log(file):
    """extracts info from a web log zip file. Returns a list of log entries"""
    #print("processing",file)
    a = []    
    # step 1: read csv
    old_type=False
    for i,line in enumerate(file):
        line = line.decode("utf8")
        if i==0 and '@timestamp' in line : # ignore first line
            old_type=True            
            #print("old",file)
            continue

            
        if old_type:
            # one log entry is contained in two lines. Join them
            if i % 2 == 1 :
                myline = line.strip()
                continue
            else:
                #myline += line
                line = myline + line
                
        
        date,*rest = line.split(",") 
        rest = ",".join(rest)

        if old_type:
            rest = rest.strip().strip('"').replace('""','"')
        else:
            rest = rest.strip()
   
        a.append(rest)
        #print(line)
            
    # step 2: extract json from string
    logs = []
    for line in a: 
                    
        # parse JSON record out of log and extract relevant record        
        try:
            json_str = json.loads( line ) 
            log = json_str["log"].strip()
            logs.append(log)
        except Exception as e:
            print("error",e)
            print("json:",rest)
            
    # step 3: parse the json and get the relevant 
    # split the web server log record into components
    rows = []
    for row in csv.reader( "\n".join(logs).splitlines(), delimiter=" " , quotechar='"') :
        #print("row",row)
     
        rows.append(row)
        
    #print("read",len(rows))

    return rows
    
    
def get_web_logs(dirs):
    """loops through directories containing compressed web log files and aggregates to a dataframe"""

    rows = [] # list of all log entries
    # open the zip and iterate over the entries
    for zipfile in [ join(mydir,f) for mydir in dirs for f in listdir(mydir) if isfile(join(mydir, f)) and f.endswith(".zip") ]:

        with ZipFile( zipfile ) as myzip:
            for i,a in enumerate(myzip.infolist()):

                if a.filename.endswith("/"): #exclude the directory
                    continue
                    
                if not a.filename.endswith(".csv"):
                    continue

                #print(a.filename)

                with myzip.open(a) as f:
                    rows.extend( process_web_log(f) )
                    
    print("extracted",len(rows),"log records")
    
    # convert into dataframe for analysis 
    df_access_logs = pd.DataFrame.from_records(rows)
    print("number logs",len(df_access_logs))
    # remove duplicates
    df_access_logs = df_access_logs.drop_duplicates()
    print("number unique logs",len(df_access_logs))

    # parse date into datetime
    df_access_logs["date_web"] = (df_access_logs[3] + df_access_logs[4]).str.replace("[","").str.replace("]","") 
    df_access_logs["date_web"] = pd.to_datetime( df_access_logs.date_web , format="%d/%b/%Y:%H:%M:%S%z" )

    # remove unnecessary columns
    df_access_logs=df_access_logs.drop([0,1,2,3,4,6,7,8,10,11,12,14,15,16,17,18,13],axis="columns")
    df_access_logs=df_access_logs.rename(columns={5:"URL",9:"browser"})

    # extract URL (remove HTTP schema and status_code)
    df_access_logs["URL"] = df_access_logs.URL.str.split(" ").str[1]

    # we are only interested in log records of the user profile
    df_access_logs=df_access_logs[df_access_logs.URL.str.contains("/share/page/user/") ]
    # extract the user name from the profile URL
    df_access_logs["user"] = df_access_logs.URL.str.split('/').str[4].str.lower()
    df_access_logs=df_access_logs.drop("URL",axis=1)

    print("min/max date",df_access_logs.date_web.min(),df_access_logs.date_web.max())
    print("number web log records",len(df_access_logs))
    
    return df_access_logs
    
def read_elios_audit(directories):
    """generator function that opens the zip, loop through the files, opens them and returns extracted records"""

    # open the zip and iterate over the entries
    for zipfile in [ join(mydir,f) for mydir in directories for f in listdir(mydir) if isfile(join(mydir, f)) and f.endswith(".zip") ]:
        with ZipFile(zipfile) as myzip:
        
            for i,a in enumerate(myzip.infolist()): 
                if a.filename.endswith("/"): # exclude directory
                    continue
                    
                if not a.filename.endswith(".json"):
                    continue
                
                my_json = json.loads(myzip.read(a).decode("utf-8")) # load the zipped file as JSON

                for entry in my_json["list"]["entries"]: # the logfile entries are contained in the list->entries list
                    entry = entry["entry"]
                    try:
                        # create flattened record from nested json
                        new_entry = {
                            "id" : entry["id"],
                            "createdAt" : entry["createdAt"],
                            "createdBy" : entry["createdByUser"]["id"],
                        }
                        # get all values
                        if "values" in entry: 
                            for k,v in entry["values"].items():
                                new_entry[k.split('/')[-1]]=v # only take last part of value path (e.g path from /alfresco-access/transaction/path)

                        yield new_entry
                    except KeyError:
                        pass
                        #print("ignoring", json.dumps(entry))

def get_elios_audit_log(dirs):
    """loops through directories containing ELIOS audit logs and extracts records. Returns dataframe"""

    # create dataframe
    df = pd.DataFrame.from_records( read_elios_audit(dirs) )
    print("number audit records",len(df))
    print("min/max date",df.createdAt.min(),df.createdAt.max())
    
    df_read = df[ (df["sub-actions"]=="readContent") & (df["type"] == "cm:person") ].copy()
    print("number of relevant audit records:",len(df_read))

    # extract user info and normalize
    df_read["user"] = df_read.user.str.lower()
    df_read["createdBy"] = df_read.createdBy.str.lower()
    df_read["user_path"] = df_read.path.str.split('/').str[-1].str.lower().str.replace("cm:","")

    # remove unnecessary columns
    df_read = df_read.drop(["sub-actions","type","version","to","from","add","delete"],axis="columns")

    df_read.createdAt = pd.to_datetime( df_read.createdAt )
    df_read=df_read.set_index("createdAt")

    #df.head()
    
    return df_read
 
def merge_frames(df_access_logs,df_suspect_logins):
    """combine the audit log and web log by joining on user and time interval. Returns dataframe of problem cases."""

    # correlate web and audit log
    # prepare dataframe of ELIOS audit log
    df_suspect_logins = df_suspect_logins.rename(columns={"user":"false_user"}) 
    df_suspect_logins = df_suspect_logins.rename(columns={"user_path":"user"}) 

    df_suspect_logins = df_suspect_logins.drop_duplicates() # remove duplicates if there are overlapping logs
    
    print("nr suspect",len(df_suspect_logins))
    print("nr web log",len(df_access_logs))
    
    
    # join the two dataframes on the date and user column. Records within 15 seconds before the audit events are matched
    tolerance = "15s"
    df_merge = pd.merge_asof(df_suspect_logins.sort_values(by="date_audit"),df_access_logs.sort_values(by="date_web"), 
                             left_on="date_audit", right_on="date_web", by="user", tolerance=pd.Timedelta(tolerance),
                            direction="nearest")

    df_problem_logins = df_merge[~df_merge.browser.isna()].sort_values(by="date_audit").query("user != 'admin'")

    # truncate to minute resolution to remove multiple matches 
    df_problem_logins["date_trunc"] = df_problem_logins.date_audit.dt.floor('Min')
    df_problem_logins=df_problem_logins.drop_duplicates(subset=["date_trunc","user","false_user"])

    # time difference between elios event and matched web log
    df_problem_logins["diff"] = (df_problem_logins.date_audit - df_problem_logins.date_web) / np.timedelta64(1,"s")

    #idx_after = df_problem_logins["diff"] > 2
    #df_problem_logins = df_problem_logins[~idx_after] # profile is loaded first 
    #print("removed",sum(idx_after),"record")

    df_problem_logins=df_problem_logins.drop("date_trunc",axis="columns")
    print("identified",len(df_problem_logins),"problem records")
    
    return df_problem_logins

def write_out_and_plot(df_problem_logins):
    """writes out the list of problem cases and produces charts"""

    print("writing stats and charts to",directory_out)

    today = date.today()

    # dd/mm/YY
    d = today.strftime("%y-%m-%d_%H-%M")


    ax= df_problem_logins.set_index("date_audit").resample("W").id.count().plot(figsize=(10,5),title="weekly number of suspect logins")
    ax.get_figure().savefig(r"{}\weekly-cases_{}".format(directory_out,d))

    df_problem_logins.to_csv(r"{}\elios-problem-logins_{}.csv".format(directory_out,d),quotechar='"',sep=";")
    

    ax=df_problem_logins.groupby(by="user").id.count().plot.barh()
    ax.set_xticks([0,1,2])
    ax.set_title("how many times did a user impersonate?")
    ax.get_figure().savefig(r"{}\chart_user_{}".format(directory_out,d))
   
    ax=df_problem_logins.groupby(by="false_user").id.count().plot.barh()
    ax.set_xticks([0,1,2,3])
    ax.set_title("how many was a user impersonated?")
    ax.get_figure().savefig(r"{}\chart_victim_{}".format(directory_out,d))


def main():
    dirs_web = [directory_web,directory_joint_logs] 
    df_access_logs = get_web_logs(dirs_web)

        
    dirs_audit = [directory_elios_audit_logs,directory_joint_logs] 
    df_read = get_elios_audit_log(dirs_audit)

    # is createdBy the same as the user attribute in the audit log for our purposes? 
    assert(len(df_read[ (df_read.user != "system") & (df_read.user != df_read.createdBy) ])==0)
    # browser field always set (since we use it as filter)
    assert(len(df_access_logs[df_access_logs.browser.isna()])==0)

    # identify suspicious records
    idx = (df_read.user_path != df_read.user)  & (df_read.user != "system")
    print("identified",sum(idx),"potentially suspicious records")

    _=df_read[idx].resample("W").id.count().plot(figsize=(10,5),title="number of potentially suspicious cases by week")
    
    df_suspect_logins = df_read[idx].drop(["path","action","createdBy"],axis="columns").reset_index().rename(columns={"createdAt":"date_audit"})
    
    
    df_problem_logins = merge_frames(df_access_logs,df_suspect_logins)
    
    print("number problem cases",len(df_problem_logins))
    print(df_problem_logins)

    write_out_and_plot(df_problem_logins)

if __name__ == "__main__":
    main()
