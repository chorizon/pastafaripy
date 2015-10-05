#!/usr/bin/python3
from bottle import route, request
from settings import config
from citoplasma.filterip import filterip
#from multiprocessing import Process, Pipe
from subprocess import Popen, PIPE
from uuid import uuid4
from shlex import quote
import hashlib
import os
import signal 
import sys
import json

if not hasattr(config, 'logs_pastafari'):
    logs='./logs'
else:
    logs=config.logs_pastafari
    
if not hasattr(config, 'python_command'):
        python_command='python3'
else:
    python_command=config.python_command

cache_file_scripts=[]

def check_hash(secret_key):

        #secret_key=request.query.get('secret_key', '')
        
        if secret_key!='':
        
            m=hashlib.sha512()
            
            code=config.SECRET_KEY+'+'+secret_key
            
            code=code.encode('utf-8')
            
            m.update(code)
            
            final_hash=m.hexdigest()
            
            if final_hash==config.SECRET_KEY_HASHED_WITH_PASS:
                return True

@route('/pastafari/<secret_key>')
def home(secret_key):  

    global cache_file_scripts

    if filterip()==True:
        
        result={'ERROR': 0, 'MESSAGE': '', 'CODE_ERROR': 0}

        if check_hash(secret_key):

            if request.query.get('script', '')!='' and request.query.get('module', '')!='' and request.query.get('category', '')!='':
                
                file=open('./settings/scripts')
                
                new_line=''
                
                if len(cache_file_scripts)==0:
                    for line in file:
                        cache_file_scripts.append(line.strip())                   
                else:
                    for line in reversed(list(file)):
                        #cache_file_scripts.append(line.strip())
                        new_line=line.strip()
                        
                        if new_line!='':
                            break
                    if new_line not in cache_file_scripts:
                        cache_file_scripts.append(new_line)
                        
                file.close()
                print(cache_file_scripts)
                uuid=str(uuid4())
                
                script=os.path.basename(request.query['category'])+'/'+os.path.basename(request.query['module'])+'/'+os.path.basename(request.query['script'])
                
                script=quote(script)
                
                if script in cache_file_scripts:
                
                    #Search script in list of scripts
                    
                    del request.query['script']
                    del request.query['module']
                    del request.query['category']
                    
                    arr_params=[ '--'+x+' '+y for x,y in request.query.items() ]
                    
                    params=' '.join(arr_params)
                    
                    args=['sudo '+python_command+' '+config.base_modules.replace('.', '/')+'/pastafari/daemon/daemon.py --script "'+script+'" --uuid '+uuid+' --arguments "'+params+'"']

                    daemon=Popen(args, bufsize=-1, executable=None, stdin=None, stdout=None, stderr=None, preexec_fn=None, close_fds=True, shell=True, cwd=None, env=None, universal_newlines=True, startupinfo=None, creationflags=0, restore_signals=True, start_new_session=True, pass_fds=())

                    #daemon.pid

                    result['UUID']=uuid

                    result['MESSAGE']='Executing script...'
                else:
                    result['ERROR']=1
                    result['MESSAGE']='Scripts not exists in database'
                    result['CODE_ERROR']=3
            else:
                result['ERROR']=1
                result['MESSAGE']='Not task specified'
                result['CODE_ERROR']=1
                
        else:
            result['ERROR']=1
            result['MESSAGE']='Not authenticated'
            result['CODE_ERROR']=2

        return result
    
    else:
        
        return 'This IP is not allowed'

@route('/pastafari/check_process/<secret_key>/<uuid>')
def check_process(secret_key, uuid):
    
    uuid=uuid.replace('/', '-')
    uuid=uuid.replace("\\", '-')
    
    if filterip()==True:
        
        result={'ERROR': 1, 'MESSAGE': '', 'CODE_ERROR' : 0}

        if check_hash(secret_key):
            if os.path.isfile(logs+'/log_'+uuid):
                f=open(logs+'/log_'+uuid)
                
                for line in f:
                    pass
                
                try:
                
                    result=json.loads(line)
                    
                    f.close()
                    
                except:
                    
                    f.close()
                    
                    result['MESSAGE']='Cannot decode json message'

    return result

if config.default_module=="pastafari":

    home = route("/")(home)
