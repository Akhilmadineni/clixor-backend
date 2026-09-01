#!/usr/bin/env python3
import argparse

def validate(passwd_record:str,group_record:str,shadow_status:str)->None:
    if passwd_record.split(":") != ["clixor-gateway","x","986","987","","/nonexistent","/usr/sbin/nologin"]:
        raise ValueError("gateway passwd authority is not exact")
    group=group_record.split(":")
    if len(group)!=4 or group[0]!="clixor-origin" or group[2]!="987" or group[3]!="":
        raise ValueError("origin group authority is not exact")
    fields=shadow_status.split()
    if len(fields)<2 or fields[0]!="clixor-gateway" or fields[1]!="L":
        raise ValueError("gateway account is not locked")

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--passwd-record",required=True); parser.add_argument("--group-record",required=True); parser.add_argument("--shadow-status",required=True); args=parser.parse_args()
    try: validate(args.passwd_record,args.group_record,args.shadow_status)
    except ValueError as error: parser.error(str(error))
    return 0
if __name__=="__main__": raise SystemExit(main())
