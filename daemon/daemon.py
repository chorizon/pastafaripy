#!/usr/bin/python3 -u

from subprocess import Popen, PIPE
from pwd import getpwuid
import argparse
import logging
import traceback
import sys
import os

#Import configuration from pastafari

#Only can be loaded by pastafari user

user=getpwuid(os.getuid())[0] 

sys.path.append('.')

from settings import config

user_pastafari='root'

#if not hasattr(config, 'user_pastafari'):
#    user_pastafari='pastafari'
#else:
#    user_pastafari=config.user_pastafari

if not hasattr(config, 'logs_pastafari'):
    logs='./logs'
else:
    logs=config.logs_pastafari
    
if not hasattr(config, 'scripts_pastafari'):
    scripts_path='./scripts'
else:
    scripts_path=config.scripts_pastafari
    
if user!=user_pastafari:
    print('Error, you need to be logged how root user for access to this script')
    exit(1)

parser = argparse.ArgumentParser(description='An Simple daemon used for execute system scripts and return logs for info to servers')

parser.add_argument('--script', help='The script to execute', required=True)

parser.add_argument('--uuid', help='The uuid of script', required=True)

parser.add_argument('--arguments', help='The arguments of script')

args = parser.parse_args()

# Execute script

try:

    #Create unique id for the log

    script=Popen(scripts_path+'/'+args.script+' '+args.arguments, bufsize=-1, executable=None, stdin=None, stdout=PIPE, stderr=PIPE, preexec_fn=None, close_fds=True, shell=True, cwd=None, env=None, universal_newlines=False, startupinfo=None, creationflags=0, restore_signals=True, start_new_session=False, pass_fds=())

    pid=str(os.getpid())
    
    #logging.basicConfig(format='{"%(levelname)s": %(message)s}', filename=logs+'/log_'+args.uuid,level=logging.INFO)

    logging.basicConfig(format='%(message)s', filename=logs+'/log_'+args.uuid,level=logging.INFO)

    logging.info('{"MESSAGE": "Running script server...", "ERROR:" 0, "EXIT_CODE": 0}')

    for line in script.stdout:
        line=line.decode('utf-8').rstrip()
        logging.info(line)
        
    #Check return code
    
    while script.poll()==None:
        pass
    
    error=''
    
    arr_error=[]
    
    if script.returncode>0:
        for line in script.stderr:
            arr_error.append(line.decode('utf-8').rstrip())
    
    error=0
    
    if script.returncode!=0:
        error=1
        logging.info('{"EXIT_CODE": "'+str(script.returncode)+'", "MESSAGE": "'+" ".join(arr_error)+'", "ERROR": '+str(error)+'}')
    

except:
    
    print("Exception in user code:")
    print("-"*60)
    traceback.print_exc(file=sys.stdout)
    print("-"*60)
    exit(1)
    

exit(0)
