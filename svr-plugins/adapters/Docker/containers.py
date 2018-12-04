#!/usr/bin/env python
# -*- coding=utf-8 -*-

import TestExecutorLib.TestValidatorsLib as TestValidatorsLib
import TestExecutorLib.TestTemplatesLib as TestTemplatesLib
import TestExecutorLib.TestOperatorsLib as TestOperatorsLib
import TestExecutorLib.TestAdapterLib as TestAdapterLib
import TestExecutorLib.TestLibraryLib as TestLibraryLib
from TestExecutorLib.TestExecutorLib import doc_public

import sys
import copy
import templates

from Libs.PyXmlDict import Xml2Dict
from Libs.PyXmlDict import Dict2Xml

from docker import errors
import docker


import logging

__NAME__="""Docker"""
AGENT_INITIALIZED = "AGENT_INITIALIZED"
AGENT_TYPE_EXPECTED='docker'
CONTAINER="container"
RUN = "run"
CREATE = "create"
GET="get"
LIST="list" 
PRUNE="prune" 


class DockerContainer(TestAdapterLib.Adapter):
	@doc_public
	def __init__ (self, parent, name=None, docker_client=None, debug=False, agentSupport=False, agent=None, shared=False, verbose=True, logEventSent=True, logEventReceived=True):
		"""
		KAFKA Producer client Adapter. Mapping of kafka-python KafkaProducer

		@param parent: parent testcase
		@type parent: testcase

		@client: Kafka broker used to boostrap at connect call (list of ip address port )
		@type bootstrap_servers: List
		
		@param agent: agent to use when this mode is activated
		@type agent: string/None
		
		@param name: adapter name used with from origin/to destination (default=None)
		@type name: string/none
		
		@param debug: active debug mode (default=False)
		@type debug:	boolean

		@param shared: shared adapter (default=False)
		@type shared:	boolean
		:type docker_client: DockerClient
		"""

		if docker_client is None:
			self.client=docker.from_env()
		else:
			self.client = docker_client

		# check agent
		if agentSupport and agent is None:
			raise TestAdapterLib.ValueException(TestAdapterLib.caller(), "Agent cannot be undefined!" )	
			
		if agentSupport:
			if not isinstance(agent, dict) : 
				raise TestAdapterLib.ValueException(TestAdapterLib.caller(), "agent argument is not a dict (%s)" % type(agent) )
			if not len(agent['name']): 
				raise TestAdapterLib.ValueException(TestAdapterLib.caller(), "agent name cannot be empty" )
			if  unicode(agent['type']) != unicode(AGENT_TYPE_EXPECTED): 
				raise TestAdapterLib.ValueException(TestAdapterLib.caller(), 'Bad agent type: %s, expected: %s' % (agent['type'], unicode(AGENT_TYPE_EXPECTED))  )
		

		TestAdapterLib.Adapter.__init__(self, name = __NAME__, parent = parent, debug=debug, realname=name,
																							agentSupport=agentSupport, agent=agent, shared=shared)
		self.parent = parent
		self.codecX2D = Xml2Dict.Xml2Dict()
		self.codecD2X = Dict2Xml.Dict2Xml(coding = None)
		self.logEventSent = logEventSent
		self.logEventReceived = logEventReceived
		self.parent = parent
		self.cfg = {}
		if agent is not None:
			self.cfg['agent'] = agent
			self.cfg['agent-name'] = agent['name']
		self.cfg['agent-support'] = agentSupport
		
		self.TIMER_ALIVE_AGT = TestAdapterLib.Timer(parent=self, duration=20, name="keepalive-agent", callback=self.aliveAgent,
																																logEvent=False, enabled=True)
		self.__checkConfig()
		
		# initialize the agent with no data
		if agent is not None:
			if self.cfg['agent-support']:
				self.prepareAgent(data={'shared': shared})
				if self.agentIsReady(timeout=30) is None: raise Exception("Agent %s is not ready" % self.cfg['agent-name'] )
				self.TIMER_ALIVE_AGT.start()
		if debug:
			self.__getKafkaClientLogger()

	def __checkConfig(self):
		"""
		"""
		self.debug("config: %s" % self.cfg)		
		self.warning('Agent used Name=%s Type=%s' % (self.cfg['agent']['name'], self.cfg['agent']['type']) ) 
	
	
	def encapsule(self, *input_layers):
		"""
		Encapsule layers in template message
		"""
		if self.cfg['agent-support']:
			layer_agent= TestTemplatesLib.TemplateLayer('AGENT')
			layer_agent.addKey(name='name', data=self.cfg['agent']['name'] )
			layer_agent.addKey(name='type', data=self.cfg['agent']['type'] )

		tpl = TestTemplatesLib.TemplateMessage()

		if self.cfg['agent-support']:
			tpl.addLayer(layer=layer_agent)
		for layer in input_layers:
			tpl.addLayer(layer=layer)

		return tpl
		
		
	def onReset(self):
		"""
		Called automaticly on reset adapter
		"""
		# stop timer
		self.TIMER_ALIVE_AGT.stop()
		
		# cleanup remote agent
		self.resetAgent()

	def receivedNotifyFromAgent(self, data):
		"""
		Function to reimplement
		"""
#		self.info( 'Notify received from agent: %s' % data )
		if 'cmd' in data:
			if data['cmd'] == AGENT_INITIALIZED:
				tpl = TestTemplatesLib.TemplateMessage()
				layer = TestTemplatesLib.TemplateLayer('AGENT')
				layer.addKey("ready", True)
				layer.addKey(name='name', data=self.cfg['agent']['name'] )
				layer.addKey(name='type', data=self.cfg['agent']['type'] )
				tpl.addLayer(layer= layer)
				self.logRecvEvent( shortEvt = "Agent Is Ready" , tplEvt = tpl )
			elif data['cmd'] == "container_{0}".format(RUN):
				self.__docker_connected = True
				tpl = templates.docker_ops(method=RUN)
				self.logRecvEvent( shortEvt = "connected", tplEvt = self.encapsule(self.containerTpl ,tpl))
			elif data['cmd'] == "container_{0}".format(CREATE):
				record_metadata = data['result']
				self.__kafka_send = True
#				rec = { "Topic":record_metadata[0], "Partition": record_metadata[1] , "Offset":record_metadata[3] , "Timestamp": record_metadata[4] ,"Checksum": record_metadata[5], "Serialized_key_size": record_metadata[6], "Serialized_value_size": record_metadata[7]}
				tpl = templates.docker_ops(method=CREATE)
				self.logRecvEvent( shortEvt = "sended", tplEvt =  self.encapsule(self.containerTpl ,tpl))
			elif data['cmd'] =="container_{0}".format(GET) :
				tpl = templates.docker_ops(method=GET)
				self.logRecvEvent( shortEvt = "flushed", tplEvt =  self.encapsule(self.containerTpl ,tpl))	
			elif data['cmd'] =="container_{0}".format(LIST) :
				partitions = data['result']
				tpl = templates.docker_ops(method=LIST)
				self.logRecvEvent( shortEvt = "list", tplEvt =  self.encapsule(self.containerTpl ,tpl))				
			elif data['cmd'] == "container_{0}".format(PRUNE):
				tpl = templates.docker_ops(method=PRUNE)
				self.logRecvEvent( shortEvt = "removed", tplEvt =  self.encapsule(self.containerTpl ,tpl))			
		else:
			self.warning( 'Notify received from agent: %s' % data )

	def receivedErrorFromAgent(self, data):
		"""
		Function to reimplement
		"""
		if "cmd" in data:
			if data['cmd'] in [ RUN, PRUNE, CREATE, GET,LIST	]:
				tpl = self.encapsule(self.containerTpl, templates.response_err(msg=data['err-msg'], method=data['cmd'] ))
				self.logRecvEvent( shortEvt = "response error", tplEvt = tpl )
				
			else:
				self.error("unknown command received: %s" % data["cmd"])
				
		else:
			self.error( 'Generic error: %s' % data )
	def receivedDataFromAgent(self, data):
		"""
		Function to reimplement
		"""
		self.warning( 'Data received from agent: %s' % data )
		
	def prepareAgent(self, data):
		"""
		Prepare agent
		"""
		self.parent.sendReadyToAgent(adapterId=self.getAdapterId(), agentName=self.cfg['agent-name'], agentData=data)
		
	def initAgent(self, data):
		"""
		Init agent
		"""
		self.parent.sendInitToAgent(adapterId=self.getAdapterId(), agentName=self.cfg['agent-name'], agentData=data)
		
	def resetAgent(self):
		"""
		Reset agent
		"""
		self.parent.sendResetToAgent(adapterId=self.getAdapterId(), agentName=self.cfg['agent-name'], agentData='')
		
	def aliveAgent(self):
		"""
		Keep alive agent
		"""
		self.parent.sendAliveToAgent(adapterId=self.getAdapterId(), agentName=self.cfg['agent-name'], agentData='')
		self.TIMER_ALIVE_AGT.restart()
		
	def sendInitToAgent(self, data):
		"""
		"""
		self.parent.sendInitToAgent(adapterId=self.getAdapterId(), agentName=self.cfg['agent-name'], agentData=data)
		
	def sendNotifyToAgent(self, data):
		"""
		"""
		self.parent.sendNotifyToAgent(adapterId=self.getAdapterId(), agentName=self.cfg['agent-name'], agentData=data)
		
	def sendResetToAgent(self, data):
		"""
		"""
		self.parent.sendResetToAgent(adapterId=self.getAdapterId(), agentName=self.cfg['agent-name'], agentData=data)
	def agentIsReady(self, timeout=1.0):
		"""
		Waits to receive "agent ready" event until the end of the timeout
		
		@param timeout: time max to wait to receive event in second (default=1s)
		@type timeout: float	
		
		@return: an event matching with the template or None otherwise
		@rtype: templatemessage		
		"""
		tpl = TestTemplatesLib.TemplateMessage()
		layer = TestTemplatesLib.TemplateLayer('AGENT')
		layer.addKey("ready", True)
		layer.addKey(name='name', data=self.cfg['agent']['name'] )
		layer.addKey(name='type', data=self.cfg['agent']['type'] )
		tpl.addLayer(layer= layer)
		evt = self.received( expected = tpl, timeout = timeout )
		return evt
		
	def __getKafkaClientLogger(self):

		logger = logging.getLogger('docker')
		logger.addHandler(logging.StreamHandler(sys.stdout))
		logger.setLevel(logging.DEBUG)

	@doc_public	
	def run(self, image, **kwargs):
		"""
		Documentation available on https://docker-py.readthedocs.io/en/stable/containers.html
		"""	
		# Log start connexion  event
		self.containerTpl = templates.docker_connect(api=CONTAINER, **kwargs)
		tpl = templates.docker_ops(method=RUN, **kwargs)
		self.logSentEvent( shortEvt = "run", tplEvt = self.encapsule(self.containerTpl,tpl))

		self.__docker_connected = False

		# Agent mode
		if self.cfg['agent-support']:
			remote_cfg = {
							'cmd': "container_{0}".format(RUN),
							'image': image,
							'kwargs': kwargs
						}
			self.sendNotifyToAgent(data=remote_cfg)
				
		else:
			try:
				container = self.client.containers.run(image, detach=True, **kwargs)
				rec = {"Id": container.id, "Labels":str(container.labels), "Name":container.name, "Short_id":container.short_id, "Status":container.status, "Image":image}
				tpl = templates.docker_ops(method=RUN, more=rec)
				self.logRecvEvent( shortEvt = "container started", tplEvt =  self.encapsule(self.containerTpl,tpl))
				return container
			except (docker.errors.ContainerError, docker.errors.ImageNotFound, docker.errors.APIError) as e:
				tpl = self.encapsule(self.containerTpl,  templates.response_err(msg=e, method=RUN ))
				self.logRecvEvent( shortEvt = "docker run error", tplEvt = tpl )
	
	@doc_public	
	def create(self, image, **kwargs):
		"""
		Documentation available on https://docker-py.readthedocs.io/en/stable/containers.html
		"""	
		tpl = templates.docker_ops(method=CREATE, **kwargs)
		self.logSentEvent( shortEvt = "req create", tplEvt = self.encapsule(self.containerTpl ,tpl))
		# Timeout for record metadata retreving

		if self.cfg['agent-support']:
			remote_cfg = {
							'cmd': "container_{0}".format(CREATE),
							'image': image,
							'kwargs': kwargs
						}
			self.sendNotifyToAgent(data=remote_cfg)
		else:
			try:
				container = self.client.containers.create(image, **kwargs)
				rec = {"Id": container.id, "Labels":str(container.labels), "Name":container.name, "Short_id":container.short_id, "Status":container.status, "Image":image}
				tpl = templates.docker_ops(method=CREATE, more=rec)
				self.logRecvEvent( shortEvt = "container created", tplEvt =  self.encapsule(self.containerTpl,tpl))
			except (docker.errors.ImageNotFound, docker.errors.APIError) as e:
				tpl = self.encapsule(self.containerTpl,  templates.response_err(msg=e, method=RUN ))
				self.logRecvEvent( shortEvt = "docker create error", tplEvt = tpl )

	@doc_public	
	def get(self, id_or_name):
		"""
		Documentation available on https://docker-py.readthedocs.io/en/stable/containers.html
		"""			
		tpl = templates.docker_ops(method=GET, id_or_name=id_or_name)
		self.logSentEvent( shortEvt = "req get", tplEvt = self.encapsule(self.containerTpl ,tpl))

		if self.cfg['agent-support']:
			remote_cfg = {
							'cmd': "container_{0}".format(GET),
							'kwargs': kwargs
						}
			self.sendNotifyToAgent(data=remote_cfg)
		else:
			try:
				container = self.client.containers.get(id_or_name)
				rec = {"Id": container.id, "Labels":str(container.labels), "Name":container.name, "Short_id":container.short_id, "Status":container.status}
				tpl = templates.docker_ops(method=GET, more=rec)
				self.logRecvEvent( shortEvt = "container found", tplEvt =  self.encapsule(self.containerTpl,tpl))
			except (docker.errors.NotFound, docker.errors.APIError) as e:
				tpl = self.encapsule(self.containerTpl,  templates.response_err(msg=e, method=GET ))
				self.logRecvEvent( shortEvt = "docker get error", tplEvt = tpl )				

	@doc_public	
	def list(self, **kwargs):
		"""
		Documentation available on https://docker-py.readthedocs.io/en/stable/containers.html
		"""		
		tpl = templates.docker_ops(method=LIST)
		self.logSentEvent( shortEvt = "container list", tplEvt = self.encapsule(self.containerTpl,tpl))	

		if self.cfg['agent-support']:
			remote_cfg = {
							'cmd': "container_{0}".format(LIST),
							'kwargs': kwargs
						}
			self.sendNotifyToAgent(data=remote_cfg)
		else:
			try:
				containers = self.client.containers.list(**kwargs)
				rec = {}
				for container in containers:
#					rec.append(  {"Id": container.id, "Labels":str(container.labels), "Name":container.name, "Short_id":container.short_id, "Status":container.status})
					rec[container.short_id] = str({"Id": container.id, "Labels":container.labels, "Name":container.name, "Short_id":container.short_id, "Status":container.status})
				tpl = templates.docker_ops(method=LIST, more=rec)
				self.logRecvEvent( shortEvt = "resp list", tplEvt =  self.encapsule(self.containerTpl,tpl))	
				return containers
			except (docker.errors.APIError) as e:
				tpl = self.encapsule(self.containerTpl,  templates.response_err(msg=e, method=LIST ))
				self.logRecvEvent( shortEvt = "docker list error", tplEvt = tpl )

	@doc_public	
	def prune(self, filters=None):
		"""
		Documentation available on https://docker-py.readthedocs.io/en/stable/containers.html
		"""		
		tpl = templates.docker_ops(method=PRUNE)
		self.logSentEvent( shortEvt = "req prune", tplEvt = self.encapsule(self.containerTpl,tpl))	

		if self.cfg['agent-support']:
			remote_cfg = {
							'cmd': "container_{0}".format(PRUNE),
							'filter': filter
						}
			self.sendNotifyToAgent(data=remote_cfg)
		else:
			try:
				containers = self.client.containers.prune(filters=filters)
				tpl = templates.docker_ops(method=PRUNE,more=containers)
				self.logRecvEvent( shortEvt = "removed", tplEvt =  self.encapsule(self.containerTpl,tpl))	
			except (docker.errors.APIError) as e:
				tpl = self.encapsule(self.containerTpl,  templates.response_err(msg=e, method=PRUNE ))
				self.logRecvEvent( shortEvt = "docker prune error", tplEvt = tpl )				
	
	@doc_public
	def isRunning(self, timeout=2, container=None):
		"""
		Wait to receive response from "run" request and match returned container datas  until the end of the timeout.
		@param timeout: time max to wait to receive event in second (default=2s)
		@type timeout: float		
		"""
		if not ( isinstance(timeout, int) or isinstance(timeout, float) ) or isinstance(timeout,bool): 
			raise TestAdapterLib.ValueException(TestAdapterLib.caller(), "timeout argument is not a float or integer (%s)" % type(timeout) )
		
		if container == None:
			container =  {"Id": TestOperatorsLib.Any(), 
													"Labels": TestOperatorsLib.Any(), 
													"Name": TestOperatorsLib.Any(), 
													"Short_id": TestOperatorsLib.Any(), 
													"Status": TestOperatorsLib.Any(), 
													"Image": TestOperatorsLib.Any()}
		expected = templates.docker_ops(method=RUN, more=container)
		# try to match the template 
		evt = self.received( expected=self.encapsule( self.containerTpl ,expected ), timeout=timeout )
		return evt

	@doc_public
	def isCreate(self, timeout=2, container=None):
		"""
		"""
		if not ( isinstance(timeout, int) or isinstance(timeout, float) ) or isinstance(timeout,bool): 
			raise TestAdapterLib.ValueException(TestAdapterLib.caller(), "timeout argument is not a float or integer (%s)" % type(timeout) )
		
		if container == None:
			container =  {"Id": TestOperatorsLib.Any(), 
													"Labels": TestOperatorsLib.Any(), 
													"Name": TestOperatorsLib.Any(), 
													"Short_id": TestOperatorsLib.Any(), 
													"Status": TestOperatorsLib.Any(), 
													"Image": TestOperatorsLib.Any()}
		expected = templates.docker_ops(method=CREATE, more=container)
		# try to match the template 
		evt = self.received( expected=self.encapsule( self.containerTpl ,expected), timeout=timeout )
		return evt	

	@doc_public
	def isGet(self, timeout=2, container=None):
		"""
		"""
		if not ( isinstance(timeout, int) or isinstance(timeout, float) ) or isinstance(timeout,bool): 
			raise TestAdapterLib.ValueException(TestAdapterLib.caller(), "timeout argument is not a float or integer (%s)" % type(timeout) )

		if container == None:
			container =  {"Id": TestOperatorsLib.Any(), 
													"Labels": TestOperatorsLib.Any(), 
													"Name": TestOperatorsLib.Any(), 
													"Short_id": TestOperatorsLib.Any(), 
													"Status": TestOperatorsLib.Any()}
		
		# construct the expected template
		expected = templates.docker_ops(method=GET, more=container)
		# try to match the template 
		evt = self.received( expected=self.encapsule( self.containerTpl ,expected), timeout=timeout )
		return evt		

	@doc_public
	def isList(self, timeout=2):
		"""
		"""
		if not ( isinstance(timeout, int) or isinstance(timeout, float) ) or isinstance(timeout,bool): 
			raise TestAdapterLib.ValueException(TestAdapterLib.caller(), "timeout argument is not a float or integer (%s)" % type(timeout) )
		
		# construct the expected template
		expected = templates.docker_ops(method=LIST)
		# try to match the template 
		evt = self.received( expected=self.encapsule( self.containerTpl ,expected), timeout=timeout )
		return evt		

	@doc_public	
	def isPrune(self, timeout=2,response=None):
		"""
		"""
		if not ( isinstance(timeout, int) or isinstance(timeout, float) ) or isinstance(timeout,bool): 
			raise TestAdapterLib.ValueException(TestAdapterLib.caller(), "timeout argument is not a float or integer (%s)" % type(timeout) )
		if response == None:
			response= { "SpaceReclaimed":TestOperatorsLib.Any()}
		expected = templates.docker_ops(method=PRUNE,more=response)
		# try to match the template 
		evt = self.received( expected=self.encapsule( self.containerTpl ,expected), timeout=timeout )
		return evt		
