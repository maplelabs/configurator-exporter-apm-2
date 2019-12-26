"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""

import json
import logging
import os
import platform
from subprocess import Popen, PIPE, STDOUT
import yaml
import signal
from socket import gethostname

from conf import *
from constants import *

CollectdData = ConfigDataDir + '/collectd_data.json'
FluentdData = ConfigDataDir + '/fluentd_data.json'
FluentbitData = ConfigDataDir + '/fluentbit_data.json'
CollectdPluginMappingFilePath = 'mapping/metrics_plugins_mapping.yaml'
FluentbitConfigurationFilePath = 'mapping/fluentbit_config_mapping.yaml'
FluentdPluginMappingFilePath = 'mapping/logging_plugins_mapping.yaml'
FluentbitPluginMappingFilePath = 'mapping/logging_fb_plugins_mapping.yaml'
TargetMappingFilePath = 'mapping/targets_mapping.yaml'
PlatformOS = platform.dist()[0].lower()
PlatformVersion = float(platform.dist()[1])

def format_response(count, data=None, error=None):
    if data is None:
        data = []
    resp = dict()
    resp['total_count'], resp['data'] = count, []

    if data:
        for item in data:
            resp['data'].append(item)
    if error:
        try:
            resp['error'] = {}
            resp['error']['code'] = error[0]
            resp['error']['text'] = error[1]
        except:
            resp['error'] = {}
            resp['error']['text'] = error[0]

    return json.dumps(resp, indent=4)


def expoter_logging(module_name):
    logger = logging.getLogger(module_name)
    # config = ConfigParser.ConfigParser()
    # config.read(os.getcwd() + os.path.sep + 'conf' + os.path.sep + 'system_config.ini')

    level = LEVEL
    logger.setLevel(eval('logging.' + level))

    log_dir = EXPORTERLOGPATH
    if not os.path.isdir(log_dir):
        os.mkdir(log_dir)

    logfile = os.path.join(log_dir, LOGFILE)

    formatter_str = FORMATTER
    formatter_str = formatter_str.replace('*', '%')
    # Set Logging Handler
    if not len(logger.handlers):
        handler = logging.FileHandler(logfile)
        handler.setLevel(eval('logging.' + level))
        formatter = logging.Formatter(formatter_str)
        handler.setFormatter(formatter)

        # add the handlers to the logger
        logger.addHandler(handler)

    return logger


logger = expoter_logging(COLLECTD_MGR)

def read_parser(filepath):
    output = []
    filep = open(filepath, 'r')
    out = {}
    for line in filep:   
        try:
            if line.startswith('[PARSER]'):
                out = {}
            elif line.startswith('\n'):
                output.append(out)
            else:
                vals = line.split( )
                if len(vals) >= 2:
                    value = ''
                    for val in vals[1:]:
                        value += str(val) + ' '
                    out[vals[0]] = value[:-1]
        except:
            logger.error("Unexpected line",line)
        continue
    output.append(out)
    filep.close()
    return output

def read_config(filepath):
    output = {}
    filep = open(filepath, 'r')
    out = {}
    for line in filep:
        try:
            if line.startswith('[INPUT]'):
                type = 'input'
                out = {}
            elif line.startswith('[FILTER]'):
                type = 'filters'
                out = {}
            elif line.startswith('[OUTPUT]'):
                type = 'output'
                out = {}
            if line.startswith('\n'):
                if type == 'filters':
                    filter = output.get(type,[])
                    filter.append(out)
                    output[type] = filter
                else:
                    output[type] = out
            else:
                vals = line.split( )
                if len(vals) >= 2:
                    value = ''
                    for val in vals[1:]:
                        value += str(val) + ' '
                    out[vals[0]] = value[:-1]
        except:
            logger.error("Unexpected line",line)
        continue
    filep.close()
    return output

def file_writer(filepath, data):
    try:
        fout = open(filepath, 'w')  # creates the file where the uploaded file should be stored
        fout.write(data)  # writes the uploaded file to the newly created file.
        fout.close()  # closes the file, upload complete.
        return True
    except:
        logger.error("Error in %s File Writting ", filepath)
        return False


def file_reader(filepath):
    data = None
    # print (filepath)
    try:
        f = open(filepath, "r")
        data = f.read()
        f.close()
    except:

        logger.error("Error in %s File Reading ", filepath)

    return data


def read_yaml_file(filename):
    with open(filename, 'r') as stream:
        try:
            return yaml.load(stream)
        except yaml.YAMLError as exc:
            return {}


def run_command(command):
    # logger.info("Run Command %s", command)
    p = Popen(command,
              stdout=PIPE,
              stderr=STDOUT)
    return iter(p.stdout.readline, b'')


def run_shell_command(command):
    # logger.info("Run Shell Command %s", command)
    p = Popen(command, stdin=PIPE,
              stdout=PIPE,
              stderr=PIPE, shell=True)
    # return iter(p.stdout.readline, b''), iter(p.stderr.readlin)
    return p.communicate()


def file_delete(path):
    command = "rm -rf " + path
    command = command.split()
    # print command
    result = run_command(command)
    for line in run_command(command):
        logger.info(line)


def create_plugin_env():
    command = "mkdir -p " + CollectdPluginConfDir + " " + ConfigDataDir
    ret = run_command(command.split())

def get_service_status(service_name):
    # result = {COLLECTD_STATUS: None, VERSION: None}
    # command = "service " + service_name + " status"
    # command = ' service collectd status'.split()
    if PlatformOS in ['centos', 'redhat'] and PlatformVersion < 7:
        command = "service " + service_name + " status"
    else:
        command = "systemctl status {0}.service".format(service_name)
    out, err = run_shell_command(command)
    if err:
        return -1
    for line in out.splitlines():
        if "stopped" in line or "inactive" in line or "failed" in line:
            return 0
        elif "running" in line or "active" in line:
            pid = get_process_id(service_name)
            if pid > 0:
                return 1
            else:
                return 0
        else:
            continue
    return -1


def start_service(service_name):
    # result = {COLLECTD_STATUS: None, VERSION: None}
    # command = "service " + service_name + " start"
    # command = ' service collectd status'.split()
    # out, err = run_shell_command(command)
    # print command
    if PlatformOS in ['centos', 'redhat'] and PlatformVersion < 7:
        command = "service " + service_name + " start"
    else:
        command = "systemctl start {0}.service".format(service_name)
    return run_shell_command(command)


def stop_service(service_name):
    # command = "service " + service_name + " stop"
    if PlatformOS in ['centos', 'redhat'] and PlatformVersion < 7:
        command = "service " + service_name + " stop"
    else:
        command = "systemctl stop {0}.service".format(service_name)
    return run_shell_command(command)


def restart_service(service_name):
    # command = "service " + service_name + " restart"
    if PlatformOS in ['centos', 'redhat'] and PlatformVersion < 7:
        command = "service " + service_name + " restart"
    else:
        command = "systemctl restart {0}.service".format(service_name)
    return run_shell_command(command)


def get_process_id(process_name):
    pid = -1
    command = "ps -ef | grep -v grep | grep " + process_name
    out, err = run_shell_command(command)

    for line in out.splitlines():
        if process_name in line:
            pid = int(line.split()[1])
    return pid


def kill_process(pid):
    os.kill(pid, signal.SIGKILL)

def get_hostname():
    hostname = "UNKNOWN"
    try:
        hostname = gethostname()
    except:
        pass
    return hostname
