"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""
"""
Logger Plugin manager
"""
import copy
from config_util import *


class FluentbitPluginManager:
    """
    Fluentd Plugin manager
    """

    def __init__(self, template_data):
        """
        Initialize member variables for Fluentd manager
        :param template_data:
        :return:
        """
        # Initialize defaults
        #self.plugin_path = os.path.sep + 'etc' + os.path.sep + 'td-agent-bit'
        self.plugin_path = "/opt/sfapm/td-agent-bit/etc/td-agent-bit"
        self.service_name = 'td-agent-bit'

        self.plugins = []
        self.enable = template_data.get(ENABLED, True)
        self.tags = template_data.get(TAGS, {})
        self.targets = template_data.get(TARGETS, [])
        self.logger_user_input = template_data

        self.plugin_config = get_fluentbit_plugins_mapping()
        self.fluentbit_config = get_fluentbit_config()
        self.target_mapping_list = get_supported_targets_mapping()

        self.plugin_post_data, self.status = [], []
        self.custom_parsers = []
        self.addon_parsers = []
        self.c_plugins = []

        # Initialize logger object
        self.logger = expoter_logging(FLUENTBIT_MGR)
        self.logger.info('Logger Object Successfully Initialized.')
        # self.logger.info('Targets Nodes : %s', str(self.nodelist))
        self.logger.info('User Input : %s', str(self.logger_user_input))

    def start(self):
        """
        Start call for td-agent service
        """
        self.logger.debug('Server - td-agent-bit - start call.')
        self.change_service_status("start")

    def restart(self):
        """
        Restart call for td-agent service
        """
        self.logger.debug('Server - td-agent-bit - restart call.')
        self.change_service_status("restart")

    def stop(self):
        """
        Stop call for td-agent service
        """
        self.logger.debug('Server - td-agent-bit - stop call.')
        self.change_service_status("stop")

    def check_status(self):
        """
        Check status call for td-agent service
        """
        self.logger.debug('Server - td-agent-bit - check_status call.')
        self.change_service_status("status")
        return self.status

    def change_service_status(self, operation):
        """
        Change service status call as per operation param passed
        :param operation: start/stop/status/restart
        :return: status message as per operation passed.
        """
        try:
            pass
        except Exception as err:
            self.logger.debug("Exception: %s ", str(err))

    def configure_plugin_data(self):
        self.logger.info('Configuring the plugin data.')
        x_comp_plugins = list()
        for x_plugin in self.logger_user_input.get(PLUGINS, []):
            temp = dict()
            temp['source'] = {}
            temp['source']['tag'] = x_plugin.get('tags', {})
            temp['name'] = x_plugin.get(NAME)
            if x_plugin.get(NAME) in self.plugin_config.keys():
                plugin = self.plugin_config.get(x_plugin.get(NAME))
                temp['collection_type'] = plugin.get('collection_type', 'logger')
                temp['config'] = x_plugin.get('config',{})
                temp['input'] = plugin.get('input')
                temp['default_conf'] = plugin.get('conf')
                if plugin.get('filters'):
                    temp['filters'] = plugin.get('filters')
                if plugin.get('transform'):
                    temp['transform'] = plugin.get('transform')
                if plugin.get('functions'):
                    temp['functions'] = plugin.get('functions')
            else:
                strr = 'In-Valid input plugin type.' + x_plugin.get(NAME)
                temp[STATUS] = "FAILED: Unsupported logging plugin component"
                continue
            self.plugins.append(temp)
        self.logger.info('Plugin data successfully Configured.')
        return True

    def configure_plugin_file(self, data):
        """
        Push configured plugin data to file
        :param data: Generate plugin data based on param passed and push config to file
        :return: True if operation is successful
        """
        # Add source.
        logger.info("Configure plugin file, data %s" %json.dumps(data))
        source_tag = str()

        #default conf
        default_conf = data.get('default_conf', {})
        if default_conf:
            memory_buffer_limit = default_conf.get('Mem_Buf_Limit','')
            refresh_Interval = default_conf.get('Refresh_Interval','')
        else:
            memory_buffer_limit = MEMORY_BUFFER_LIMIT
            refresh_Interval = REFRESH_INTERVAL
        ui_config = data.get('config', {})
        logpath = ''
        logfilter = ''
        ignorelines = ''
        if ui_config:
            logpath = ui_config.get('log_paths','')
            logfilter = ui_config.get('filters',{}).get('level',[])
            ignorelines = ui_config.get('ignore_older_than','')

        if ignorelines:
            if not(ignorelines[:-1].isdigit() and (ignorelines[-1:] == 'm' or ignorelines[-1:] == 'h' or ignorelines[-1:] == 'd')):
                ignorelines = ''

        if not logfilter:
            logfilter = ['error']
        
        lines = ['[INPUT]']
        for key, val in data.get('input', {}).iteritems():
            if logpath and key == 'Path':
                val = logpath
            lines.append('    ' + str(key) + ' ' + str(val))
        lines.append('    ' + 'Refresh_Interval' + ' ' + str(refresh_Interval))
        lines.append('    ' + 'Mem_Buf_Limit' + ' ' + str(memory_buffer_limit))
        lines.append('    ' + 'Tag' + ' ' + str(data.get('name','')))
        lines.append('    ' + 'Path_Key' + ' ' + 'file')
        lines.append('    ' + 'Skip_Long_Lines' + ' ' + 'On')

        if ignorelines:
            lines.append('    ' + 'Ignore_Older' + ' ' + str(ignorelines))
        lines.append('')

        for filter in data.get('filters', []):
            lines.append('[FILTER]')
            lines.append('    ' + 'Match' + ' ' + str(data.get('name','')))
            for key, val in filter.iteritems():
                lines.append('    ' + str(key) + ' ' + str(val))
            lines.append('')
        #check tags
        if self.tags or data.get('transform', {}):
            lines.append('[FILTER]')
            lines.append('    ' + 'Name' + ' record_modifier')
            lines.append('    ' + 'Match' + ' ' + str(data.get('name','')))
            if self.tags:
                for tag_key, tag_val in self.tags.items():
                        lines.append('    ' + 'Record'+ ' ' +'_tag_' + str(tag_key) + ' ' + str(tag_val))
            if data.get('transform', {}):
                for key, val in data.get('transform', {}).iteritems():
                    lines.append('    ' + 'Record'+ ' ' + str(key) + ' ' + str(val))
            lines.append('')

        
        if logfilter:
            loglevels = ''
            for logf in logfilter:
                loglevels+=str(logf)+','
            lines.append('[FILTER]')
            lines.append('    ' + 'Name' + ' record_modifier')
            lines.append('    ' + 'Match' + ' ' + str(data.get('name','')))
            lines.append('    ' + 'Record'+ ' ' + 'log_filters' + ' ' + str(loglevels[:-1]))
            lines.append('')

        #adding timestamp
        lines.append('[FILTER]')
        lines.append('    ' + 'Name' + ' lua')
        lines.append('    ' + 'Match' + ' ' + str(data.get('name','')))
        lines.append('    ' + 'script' + ' ' + LUA_SCRIPTFILE)
        lines.append('    ' + 'call' + ' ' + 'addtimeGMToffset_millisecond')
        lines.append('')

        #adding timestamp
        
        if data.get('functions', []):
            for fun in data.get('functions', []):
                lines.append('[FILTER]')
                lines.append('    ' + 'Name' + ' lua')
                lines.append('    ' + 'Match' + ' ' + str(data.get('name','')))
                lines.append('    ' + 'script' + ' ' + LUA_SCRIPTFILE)
                lines.append('    ' + 'call' + ' ' + str(fun))
                lines.append('')

        #adding logfilter
        if logfilter:
            lines.append('[FILTER]')
            lines.append('    ' + 'Name' + ' lua')
            lines.append('    ' + 'Match' + ' ' + str(data.get('name','')))
            lines.append('    ' + 'script' + ' ' + LUA_SCRIPTFILE)
            lines.append('    ' + 'call' + ' ' + 'filter_log')
            lines.append('')

        if logfilter:
            lines.append('[FILTER]')
            lines.append('    ' + 'Name' + ' record_modifier')
            lines.append('    ' + 'Match' + ' ' + str(data.get('name','')))
            lines.append('    ' + 'Remove_key'+ ' ' + 'log_filters')
            lines.append('    ' + 'Remove_key'+ ' ' + '@timestamp')
            lines.append('')

        for x_targets in self.targets:
            if STATUS not in x_targets:
                if x_targets.get('store_type') and data.get('collection_type','') == x_targets.get('store_type'):
                    lines.append('[OUTPUT]')
                    lines.append('    ' + 'Name' + ' es')
                    lines.append('    ' + 'Match' + ' ' + str(data.get('name','')))
                    lines.append('    ' + 'Buffer_Size' + ' ' + '2MB')
                    if x_targets.get('host',''):
                        lines.append('    ' + 'Host' + ' ' + str(x_targets.get('host','')))
                    if x_targets.get('port',''):
                        lines.append('    ' + 'Port' + ' ' + str(x_targets.get('port','')))
                    if x_targets.get('index',''):
                        lines.append('    ' + 'Index' + ' ' + str(x_targets.get('index','')) + '_write')
                    if x_targets.get('username',''):
                        lines.append('    ' + 'HTTP_User' + ' ' + str(x_targets.get('username','')))
                    if x_targets.get('password',''):
                        password = x_targets.get('password','')
                        lines.append('    ' + 'HTTP_Passwd' + ' ' + str(password))
                    if x_targets.get('protocol','') and x_targets.get('protocol','') == 'https':
                        lines.append('    ' + 'tls' + ' On')
                        lines.append('    ' + 'tls.verify' + ' Off')
                    lines.append('    ' + 'Type' + ' ' + DOCUMENT)
            #if plugin_name != "linux-syslog":
                    #   lines.append('    ' + 'Time_Key' + ' ' + 'time')
                    lines.append('')

        filename = self.plugin_path + os.path.sep + data.get('name') +'.conf'
        self.plugin_post_data.append((filename, '\n'.join(lines)))
        return True

    def generate_plugins(self):
        """
        Generate plugin data
        :return: true if operation is successful
        """
        # Generate the files in the salt dir
        logger.debug("Generate plugins configs")
        self.configure_plugin_data()
        for x_plugin in self.plugins:
            logger.debug(str(STATUS not in x_plugin))
            if STATUS not in x_plugin:
                self.logger.debug('Configuring the plugin: %s', (str(x_plugin)))
                self.configure_plugin_file(x_plugin)
        return True

    def generate_fluentbit_parser_file(self):
        self.logger.info('Generating fluentbit parser file (parsers.conf).')
        lines = []
        for parser in self.fluentbit_config.get('parsers', []):
            lines.append('[PARSER]')
            for key, val in parser.iteritems():
                lines.append('    ' + str(key) + ' ' + str(val))
            lines.append('')
        for par in self.custom_parsers:
            lines.append('[PARSER]')
            for key, val in par.iteritems():
                lines.append('    ' + str(key) + ' ' + str(val))
            lines.append('    ' + "Time_Keep" + ' ' + "On")
            lines.append('')

        for addonpar in self.addon_parsers:
            lines.append('[PARSER]')
            for key, val in addonpar.iteritems():
                lines.append('    ' + 'Regex' + ' ' + str(val))
                lines.append('    ' + 'Name' + ' ' + str(key))
            lines.append('    ' + 'Format' + ' ' + 'regex')
            lines.append('')

        filename = self.plugin_path + os.path.sep + 'parsers.conf'
        self.plugin_post_data.append((filename, '\n'.join(lines)))
        return True
             
    def generate_fluentbit_config_file(self):
        """
        Generate fluentd config file
        :return: True if operation is successful
        """
        self.logger.info('Generating fluentd config file (td-agent-bit.conf).')
        lines = []
        lines.append('[SERVICE]')
        for key, val in self.fluentbit_config.get('config', {}).iteritems():
            lines.append('    ' + str(key) + ' ' + str(val))

        for x_plugin in self.plugins:
            if STATUS not in x_plugin:
                lines.append('@INCLUDE ' + x_plugin.get('name') + '.conf')
        lines.append('@INCLUDE ' + 'manual-*.conf')

        for x_plugin in self.c_plugins:
            lines.append('@INCLUDE ' + x_plugin.get('name') + '.conf')

        lines.append('\n')
        filename = self.plugin_path + os.path.sep + 'td-agent-bit.conf'
        self.plugin_post_data.append((filename, '\n'.join(lines)))
        return True

    def create_conf_files(self):
        for cnf in self.plugin_post_data:
            file_writer(cnf[0], cnf[1])

    def custom_plugins(self):
        self.c_plugins = self.logger_user_input.get(CUSTOM_PLUGINS, [])
        for x_plugin in self.c_plugins:
            par = x_plugin.get('parser')
            plu = x_plugin.get('plugin')
            #name = x_plugin.get('name')
            #collection_type = x_plugin.get('collection_type')
            #field_discovery = x_plugin.get('field_discovery')
            if par:
                parser_obj = read_parser(par)
                if parser_obj:
                    self.custom_parsers.extend(parser_obj)
            if plu:
                plugin_obj = read_config(plu)
                if plugin_obj:
                    self.logger.info(str(plugin_obj))
                    self.build_custom_plugin(plugin_obj,x_plugin)

    def build_custom_plugin(self,data,plugin):
        name = plugin.get('name')
        collection_type = plugin.get('collection_type')
        field_discovery = plugin.get('field_discovery','')
        numberfields = plugin.get('number_fields','')
        stringfields = plugin.get('string_fields','')
        timefields = plugin.get('time_fields','')
        offset = plugin.get('add_offset','')
        logpath = plugin.get('log_path','')
        parsers = plugin.get('field_extracters',{}) 
        toslog = False
        if not collection_type:
            collection_type = 'logger'

        lines = ['[INPUT]']
        for key, val in data.get('input', {}).iteritems():
            if logpath and key == 'Path':
                val = logpath
            if key == 'Path' and 'tosbqa' in val:
                toslog = True
            lines.append('    ' + str(key) + ' ' + str(val))
        lines.append('')
        for filter in data.get('filters', []):
            lines.append('[FILTER]')
            for key, val in filter.iteritems():
                lines.append('    ' + str(key) + ' ' + str(val))
            lines.append('')

        for key, val in parsers.iteritems():
            self.addon_parsers.append({name+'_'+key:val})
            lines.append('[FILTER]')
            lines.append('    ' + 'Name' + ' ' + 'parser')
            lines.append('    ' + 'Preserve_Key' + ' ' + 'On')
            lines.append('    ' + 'Key_Name' + ' ' + 'message')
            lines.append('    ' + 'Parser' + ' ' + name+'_'+key)
            lines.append('    ' + 'Reserve_Data' + ' ' + 'On')
            lines.append('    ' + 'Match' + ' ' + name)
            lines.append('')

        lines.append('[FILTER]')
        lines.append('    ' + 'Name' + ' lua')
        lines.append('    ' + 'Match' + ' ' + name)
        lines.append('    ' + 'script' + ' ' + LUA_SCRIPTFILE)
        if offset == 'On':
            lines.append('    ' + 'call' + ' ' + 'addtimeGMToffset_millisecond')
        else:
            lines.append('    ' + 'call' + ' ' + 'addtime_millisecond')
        lines.append('')

        lines.append('[FILTER]')
        lines.append('    ' + 'Name' + ' record_modifier')
        lines.append('    ' + 'Match' + ' ' + name)
        if numberfields:
            lines.append('    ' + 'Record'+ ' ' + 'numberfields'+ ' ' + str(numberfields))
        if stringfields:
            lines.append('    ' + 'Record'+ ' ' + 'stringfields'+ ' ' + str(stringfields))
        if timefields:
            lines.append('    ' + 'Record'+ ' ' + 'timefields'+ ' ' + str(timefields))
        lines.append('')

        if field_discovery == 'On':
            lines.append('[FILTER]')
            lines.append('    ' + 'Name' + ' lua')
            lines.append('    ' + 'Match' + ' ' + name)
            lines.append('    ' + 'script' + ' ' + LUA_SCRIPTFILE)
            lines.append('    ' + 'call' + ' ' + 'defaultdiscovery')
            lines.append('')

        lines.append('[FILTER]')
        lines.append('    ' + 'Name' + ' lua')
        lines.append('    ' + 'Match' + ' ' + name)
        lines.append('    ' + 'script' + ' ' + LUA_SCRIPTFILE)
        lines.append('    ' + 'call' + ' ' + 'defaultextraction')
        lines.append('')

        lines.append('[FILTER]')
        lines.append('    ' + 'Name' + ' record_modifier')
        lines.append('    ' + 'Match' + ' ' + name)
        if self.tags:
            for tag_key, tag_val in self.tags.items():
                lines.append('    ' + 'Record'+ ' ' +'_tag_' + str(tag_key) + ' ' + str(tag_val))
        lines.append('    ' + 'Record'+ ' ' + '_documentType'+ ' ' + name)
        if toslog:
            lines.append('    ' + 'Record'+ ' ' + '_plugin'+ ' ' + 'tos')
        else:
            lines.append('    ' + 'Record'+ ' ' + '_plugin'+ ' ' + name)
        lines.append('')

        for x_targets in self.targets:
            if STATUS not in x_targets:
                if x_targets.get('store_type') and collection_type == x_targets.get('store_type'):
                    lines.append('[OUTPUT]')
                    output_dict = data.get('output', {})
                    output_dict['Name'] = 'es'
                    output_dict['Host'] = str(x_targets.get('host',''))
                    output_dict['Index'] = str(x_targets.get('index','')) + '_write'
                    output_dict['Port'] = str(x_targets.get('port',''))
                    if x_targets.get('username',''):
                        output_dict['HTTP_User'] = str(x_targets.get('username',''))
                    if x_targets.get('password',''):
                        password = x_targets.get('password','')
                        output_dict['HTTP_Passwd'] = str(password)
                    output_dict['Buffer_Size'] = '2MB'
                    # output_dict['Retry_Limit'] = 'False'
                    self.logger.error(str(x_targets.get('protocol','')))
                    if x_targets.get('protocol','') and x_targets.get('protocol','') == 'https':
                        output_dict['tls'] = 'On'
                        output_dict['tls.verify'] = 'Off'
                    output_dict['Type'] = DOCUMENT
                    output_dict['Match'] = str(name)
                    #output_dict['Time_Key'] = 'time'
 
                    for key, val in output_dict.iteritems():
                        lines.append('    ' + str(key) + ' ' + str(val))
                    lines.append('')

        filename = self.plugin_path + os.path.sep + name +'.conf'
        self.plugin_post_data.append((filename, '\n'.join(lines)))

    def bulid_set_config_result(self):
        logging = {}

        for x_plugin in self.plugins:
            if STATUS not in x_plugin:
                x_plugin[STATUS] = "SUCCESS: Plugin configured"

        logging[PLUGINS] = self.plugins

        for x_targets in self.targets:
            if STATUS not in x_targets:
                x_targets[STATUS] = "SUCCESS: targets configured"

        logging[TARGETS] = self.targets
        logging[ENABLED] = self.enable
        return logging

    def store_set_config(self):
        """

        :return:
        """
        error_msg = ""
        logging = {}
        plugins_list = copy.deepcopy(self.plugins)
        targets_list = copy.deepcopy(self.targets)
        try:
            # Build plugin Result
            for i in range(len(plugins_list)):
                if STATUS in plugins_list[i] and "FAILED" in plugins_list[i][STATUS]:
                    del plugins_list[i]
                    continue

                if STATUS in plugins_list[i]:
                    del plugins_list[i][STATUS]

            logging[PLUGINS] = plugins_list

            mapping_list = get_supported_targets_mapping()
            for i in range(len(targets_list)):
                if STATUS in targets_list[i] and "FAILED" in targets_list[i][STATUS]:
                    del targets_list[i]
                    continue

                if STATUS in targets_list[i]:
                    del targets_list[i][STATUS]

            logging[TARGETS] = targets_list
            logging[ENABLED] = self.enable
            logging[TAGS] = self.tags
            # Store config data
            file_writer(FluentbitData, json.dumps(logging))
            self.logger.info(" maintain set configuration data for configurator to use")

        except Exception as e:
            error_msg += "Logging configutration storing failed: "
            error_msg += str(e)
            self.logger.error(error_msg)

    def verify_targets(self):
        for x_targets in self.targets:
            if x_targets[TYPE] in self.target_mapping_list.keys():
                keys = self.target_mapping_list[x_targets[TYPE]].keys()
                for key in x_targets.keys():
                    if key not in keys:
                        del x_targets[key]
            else:
                x_targets[STATUS] = "FAILED: Unsupported logging targets"

    def set_config(self):
        """
        configure fluentd
        :return:
        """
        return_dict = {}
        error_msg = ""
        try:
            self.logger.info('Deployment Started.')
            self.logger.debug(
                'Enable : ' + str(self.enable))

            success, error_msg = delete_fluentbit_config()
            self.verify_targets()
            self.custom_plugins()
            self.generate_plugins()
            self.generate_fluentbit_parser_file()
            self.generate_fluentbit_config_file()

            self.logger.info('Pushing the configs to the target node.')
            self.logger.debug('self.plugin_post_data' +
                              json.dumps(self.plugin_post_data))
            self.create_conf_files()
            self.logger.info("Stop fluentbit process")
            change_fluentbit_status(STOP)
            if self.enable:
                # self.restart()
                try:
                    for plugin in self.plugins:
                        files = plugin.get("source", {}).get("path")
                        if files:
                            for filepath in files.split(','):
                                self.logger.info("changing file %s permission", filepath)
                                set_log_file_permission(filepath, 'o+r,o+x')
                except:
                    self.logger.error("Error in changing file permission")
                self.logger.info("Start fluentbit process")
                change_fluentbit_status(START)

            return_dict = self.bulid_set_config_result()
            self.logger.info("Bulid set configuration result completed")

            # Stored copnfiguration locally.
            self.store_set_config()

        except Exception as e:
            error_msg += str(e)
            return_dict[ERROR] = error_msg
            self.logger.error("Set fluentbit config failed")
            self.logger.error(str(e))

        return return_dict
