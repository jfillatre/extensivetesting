#!/usr/bin/env python
# -*- coding: utf-8 -*-

# -------------------------------------------------------------------
# Copyright (c) 2010-2017 Denis Machard
# This file is part of the extensive testing project
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301 USA
# -------------------------------------------------------------------
from functools import wraps
from pycnic.core import WSGI, Handler
from pycnic.errors import HTTP_401, HTTP_400, HTTP_500, HTTP_403, HTTP_404

from wsgiref.simple_server import make_server
from wsgiref.simple_server import WSGIRequestHandler

import multiprocessing

import threading
import logging
import sys
import os
import platform
import json
import wrapt
import base64

from Libs import Settings, Logger

try:
    import Context
    import ProjectsManager
    import RepoTests
    import RepoPublic
    import RepoArchives
    import TaskManager
    import AgentsManager
    import ProbesManager
    import RepoAdapters
    import RepoLibraries
    import ToolboxManager
    import UsersManager
    import CliFunctions
    import HelperManager
    import StatsManager
except ImportError: # python3 support
    from . import Context
    from . import ProjectsManager
    from . import RepoTests
    from . import RepoPublic
    from . import RepoArchives
    from . import TaskManager
    from . import AgentsManager
    from . import ProbesManager
    from . import RepoAdapters
    from . import RepoLibraries
    from . import ToolboxManager
    from . import UsersManager
    from . import CliFunctions
    from . import HelperManager
    from . import StatsManager
    
try:
    import hashlib
    sha1_constructor = hashlib.sha1
except ImportError as e: # support python 2.4
    import sha
    sha1_constructor = sha.new
    
import Libs.FileModels.TestSuite as TestSuite
import Libs.FileModels.TestUnit as TestUnit
import Libs.FileModels.TestPlan as TestPlan
import Libs.FileModels.TestAbstract as TestAbstract
import Libs.FileModels.TestConfig as TestConfig

class EmptyValue(Exception): pass

def _get_user(request):
    """
    Lookup a user session or return None if one doesn't exist
    """
    sess_id = request.cookies.get("session_id")
    if sess_id is None:
        # new in v17, checking authorization header
        authorization = request.get_header(name="Authorization", default=None)
        if authorization is not None:
            userP = Context.instance().apiAuthorizationV2(authorization=authorization)
            if userP is None:
                raise HTTP_401("Invalid credentials")
            else:
                return userP
        else:
            raise HTTP_401("Authorization header not detected")
        # end of new
    else:
        if sess_id in Context.instance().getSessions():
            return Context.instance().getSessions()[sess_id]
        else:
            raise HTTP_401("Invalid session")

@wrapt.decorator
def _to_yaml(wrapped, instance, args, kwargs):
    """
    New in v17
    public decorator for yaml generator
    """
    return wrapped(*args, **kwargs)
    
@wrapt.decorator
def _to_yaml_defs(wrapped, instance, args, kwargs):
    """
    New in v17
    public decorator for yaml generator
    """
    return wrapped(*args, **kwargs)
    
@wrapt.decorator
def _to_yaml_tags(wrapped, instance, args, kwargs):
    """
    New in v17
    public decorator for yaml generator
    """
    return wrapped(*args, **kwargs)
    
"""
Swagger object definitions
"""
class SwaggerDefinitions(object):
    """
    """
    #@_to_yaml_defs
    def ResponseGeneric(self):
        """
        type: object
        properties:
          cmd:
            type: string
          message:
            type: string
        """
        pass
    
"""
Swagger tags
"""
class SwaggerTags(object):
    """
    """
    @_to_yaml_tags
    def session(self):
        """
        Everything about your session
        """
        pass
    @_to_yaml_tags
    def variables(self):
        """
        Everything to manage projects variables
        """
        pass
    @_to_yaml_tags
    def tests(self):
        """
        Everything to manage your tests
        """
        pass
    @_to_yaml_tags
    def tasks(self):
        """
        Everything to manage your tasks
        """
        pass
    @_to_yaml_tags
    def public(self):
        """
        Everything to manage your tasks
        """
        pass 
    @_to_yaml_tags
    def results(self):
        """
        Everything to manage your test results
        """
        pass 
    @_to_yaml_tags
    def reports(self):
        """
        Everything to get your test reports
        """
        pass  
"""
Sessions handlers
"""

"""
Session handlers
"""
class SessionLogin(Handler):
    """
    /rest/session/login
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - session
        summary: Authenticate client
        description: ''
        operationId: sessionLogin
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: body
            in: body
            required: true
            schema:
              required: [login,password]
              properties:
                login:
                  type: string
                password:
                  type: string
                  description: sha1 password
                channel-id:
                  type: string
                client-version:
                  type: string
                client-platform:
                  type: boolean
                client-portable:
                  type: string
        responses:
          '200':
            description: Logged in
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                expires:
                  type: integer
                user_id:
                  type: integer
                session_id:
                  type: string
                project_id:
                  type: integer
            examples:
              application/json: |
                {
                  "expires": 86400, 
                  "user_id": 2, 
                  "cmd": "/session/login", 
                  "session_id": "NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M", 
                  "message": "Logged in", 
                  "project_id": 1
                }
            headers:
              Set-Cookie:
                type: string
                description: |
                  session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M;expires=Wed, 10-May-2017 06:32:57 GMT; path=/ 
          '401':
            description: Invalid login | Account disabled | Access not authorized | Invalid  password
          '400':
            description: Bad request provided
        """
        try:
            login = self.request.data.get("login")
            password = self.request.data.get("password")
            if not login or not password:  raise EmptyValue("Please specify login and password")
            
            channelId = self.request.data.get("channel-id")
            clientVersion = self.request.data.get("client-version")
            clientPlatform = self.request.data.get("client-platform")
            clientPortable = self.request.data.get("client-portable")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # check user access 
        (userSession, expires) = Context.instance().apiAuthorization(login=login, password=password)
        
        if userSession == Context.instance().CODE_NOT_FOUND:
            raise HTTP_401("Invalid login")

        if userSession == Context.instance().CODE_DISABLED:
            raise HTTP_401("Account disabled")

        if userSession == Context.instance().CODE_FORBIDDEN:
            raise HTTP_401("Access not authorized")

        if userSession == Context.instance().CODE_FAILED:
            raise HTTP_401("Invalid  password")

        lease = Settings.get('Users_Session', 'max-expiry-age') #in seconds
        userProfile = Context.instance().getSessions()[userSession]
        
        self.response.set_cookie(key="session_id", value=userSession, expires=expires, path='/', domain="") 

        # get levels
        levels = Context.instance().getLevels(userProfile=userProfile)
        
        if channelId is not None:
            if not isinstance(channelId, list): raise HTTP_400("Bad channel-id provided in request, list expected")
            if len(channelId) != 2: raise HTTP_400("Bad len channel-id provided in request, list of 2 elements expected")
            
            channelId = tuple(channelId)
            user = { 'address' : channelId, 'profile': userProfile }
            registered = Context.instance().registerUser(user=user)
            
        _rsp = {    "cmd": self.request.path, "message":"Logged in", 
                    "session_id": userSession, "expires": int(lease), 
                    "user_id": userProfile['id'], "levels": levels,
                    "project_id":  userProfile['defaultproject'], 
                    }
        
        # checking version 
        if clientVersion is not None and clientPlatform is not None and clientPortable is not None:
            success, newVersion, newPkg = Context.instance().checkClientUpdate( currentVersion= clientVersion, 
                                                                                systemOs = clientPlatform, 
                                                                                portable = clientPortable )
            clientAvailable = False
            if success == Context.instance().CODE_ERROR:
                raise HTTP_500("error to check if a new client is available")
            if success == Context.instance().CODE_OK:
                clientAvailable = True
            _rsp["client-available"] = clientAvailable
            _rsp["version"] = newVersion 
            _rsp["name"] = newPkg
            
        return _rsp
        
class SessionLogout(Handler):
    """
    /rest/session/logout
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - session
        summary: Logout client
        description: ''
        operationId: sessionLogout
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: Logged out | Not logged in
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "logged out",
                  "cmd": "/session/logout"
                }
            headers:
              Set-Cookie:
                type: string
                description: |
                  session_id=DELETED;expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/ 
        """
        sess_id = self.request.cookies.get("session_id")
        
        if sess_id in Context.instance().getSessions():
            del Context.instance().getSessions()[sess_id]
            self.response.delete_cookie("session_id")
            return {  "cmd": self.request.path, "message":"logged out" } 

        return { "cmd": self.request.path, "message":"Not logged in" }
        
class SessionRefresh(Handler):
    """
    /rest/session/refresh
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - session
        summary: Refresh session
        description: ''
        operationId: sessionRefresh
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: Session refreshed
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "session refreshed",
                  "cmd": "/session/refresh"
                }
            headers:
              Set-Cookie:
                type: string
                description: |
                  session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M;expires=Wed, 10-May-2017 06:32:57 GMT; path=/ 
          '401':
            description: Access denied
        """
        sess_user = _get_user(request=self.request)
        sess_id = self.request.cookies.get("session_id")
        
        expires = Context.instance().updateSession(sessionId=sess_id)
        self.response.set_cookie(key="session_id", value=sess_id, expires=expires, path='/', domain="") 
        return { "cmd": self.request.path, "message":"session refreshed" }
        
class SessionContext(Handler):
    """
    /rest/session/context
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - session
        summary: Context session
        description: ''
        operationId: sessionContext
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: Session refreshed
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "context": "xxxxxxxxxxxx",
                  "cmd": "/session/context"
                }
          '401':
            description: Access denied
        """
        user_profile = _get_user(request=self.request)
        
        context = Context.instance().getInformations(user=user_profile['login'], b64=True)
        
        return { "cmd": self.request.path, "context": context }
        
class SessionContextAll(Handler):
    """
    /rest/session/context/all
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - session
        summary: get full context
        description: ''
        operationId: sessionContextAll
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: Session refreshed
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "context": "xxxxxxxxxxxx",
                  "cmd": "/session/context"
                }
          '401':
            description: Access denied
        """
        user_profile = _get_user(request=self.request)
        
        USER_CTX = Context.UserContext(login=user_profile["login"])
        
        rsp = { "cmd": self.request.path }
        
        rsp['probes'] = ProbesManager.instance().getRunning(b64=True)
        rsp['probes-installed'] = ProbesManager.instance().getInstalled(b64=True)
        rsp['probes-stats'] = ProbesManager.instance().getStats(b64=True)
        rsp['probes-default'] = ProbesManager.instance().getDefaultProbes(b64=True)

        rsp['agents'] = AgentsManager.instance().getRunning(b64=True)
        rsp['agents-installed'] = AgentsManager.instance().getInstalled(b64=True)
        rsp['agents-stats'] = AgentsManager.instance().getStats(b64=True)
        rsp['agents-default'] = AgentsManager.instance().getDefaultAgents(b64=True)
        
        rsp['projects'] = USER_CTX.getProjects(b64=True)
        rsp['default-project'] = USER_CTX.getDefault()
        
        _, _, archs, stats_archs = RepoArchives.instance().getTree(b64=True,  project=USER_CTX.getDefault())
        rsp['archives'] =  archs
        rsp['stats-repo-archives'] = stats_archs

        rsp['tasks-running'] = TaskManager.instance().getRunning(b64=True, user=USER_CTX)
        rsp['tasks-waiting'] = TaskManager.instance().getWaiting(b64=True, user=USER_CTX)
        rsp['tasks-history'] = TaskManager.instance().getHistory(b64=True, user=USER_CTX)
        rsp['tasks-enqueued'] = TaskManager.instance().getEnqueued(b64=True)

        _, _, tests, stats_tests = RepoTests.instance().getTree(b64=True, project=USER_CTX.getDefault() )
        rsp['repo'] = tests
        rsp['stats-repo-tests'] = stats_tests
        
        rsp['help'] = HelperManager.instance().getHelps()
        rsp['stats'] = StatsManager.instance().getStats()
        
        rsp['stats-server'] = Context.instance().getStats(b64=True)
        rsp['backups-repo-tests'] = RepoTests.instance().getBackups(b64=True)
        rsp['backups-repo-adapters'] = RepoAdapters.instance().getBackups(b64=True)
        rsp['backups-repo-libraries'] = RepoLibraries.instance().getBackups(b64=True)
        rsp['backups-repo-archives'] = RepoArchives.instance().getBackups(b64=True)
            
        _, _, adps, stats_adps = RepoAdapters.instance().getTree(b64=True)
        rsp['repo-adp'] = adps
        rsp['stats-repo-adapters'] = stats_adps
        
        _, _, libs, stats_libs = RepoLibraries.instance().getTree(b64=True)
        rsp['repo-lib-adp'] = libs
        rsp['stats-repo-libraries'] = stats_libs
        
        rsp['rn'] = Context.instance().getRn(pathRn=Settings.getDirExec(), b64=True) 
        rsp['rnAdp'] = RepoAdapters.instance().getRn(b64=True)
        rsp['rnLibAdp'] = RepoLibraries.instance().getRn(b64=True)
        rsp['rnToolbox'] = ToolboxManager.instance().getRn(b64=True)
        rsp['informations'] = Context.instance().getInformations(user=USER_CTX, b64=True)
        
        del USER_CTX
        
        return rsp
        
"""
Tasks handlers
"""
class TasksRunning(Handler):
    """
    /rest/tasks/running
    """
    @_to_yaml    
    def get(self):
        """
        tags:
          - tasks
        summary: Get all my running tasks or all with admin level
        description: ''
        operationId: tasksRunning
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: Running tasks
            schema :
              properties:
                cmd:
                  type: string
                tasks-running:
                  type: array
            examples:
              application/json: |
                {
                  "tasks-running": [],
                  "cmd": "/tasks/running"
                }
          '401':
            description: Access denied
        """
        user_profile = _get_user(request=self.request)
        
        _userCtx = Context.UserContext(login=user_profile['login'])
        if user_profile['administrator']: _userCtx = None
        
        running = TaskManager.instance().getRunning(b64=False, user=_userCtx)
        return { "cmd": self.request.path, "tasks-running": running }
        
class TasksWaiting(Handler):
    """
    /rest/tasks/waiting
    """
    @_to_yaml    
    def get(self):
        """
        tags:
          - tasks
        summary: Get all my waiting tasks or all with admin level
        description: ''
        operationId: tasksWaiting
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: Waiting tasks
            schema :
              properties:
                cmd:
                  type: string
                tasks-waiting:
                  type: array
            examples:
              application/json: |
                {
                  "tasks-waiting": [],
                  "cmd": "/tasks/waiting"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)

        _userCtx = Context.UserContext(login=user_profile['login'])
        if user_profile['administrator']: _userCtx = None
        
        waiting = TaskManager.instance().getWaiting(b64=False, user=_userCtx)
        return { "cmd": self.request.path, "tasks-waiting": waiting }
        
class TasksHistory(Handler):
    """
    /rest/tasks/history
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - tasks
        summary: Get my partial history tasks or all with admin level
        description: ''
        operationId: tasksHistory
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: History tasks
            schema :
              properties:
                cmd:
                  type: string
                tasks-history:
                  type: array
            examples:
              application/json: |
                {
                  "tasks-history": [],
                  "cmd": "/tasks/history"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)

        _userCtx = Context.UserContext(login=user_profile['login'])
        if user_profile['administrator']: _userCtx = None
        
        history = TaskManager.instance().getHistory(b64=False, user=_userCtx)
        return { "cmd": self.request.path, "tasks-history": history }
        
class TasksHistoryAll(Handler):
    """
    /rest/tasks/history/all
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - tasks
        summary: Get all my history tasks or all with admin level
        description: ''
        operationId: tasksHistoryAll
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: History tasks
            schema :
              properties:
                cmd:
                  type: string
                tasks-history:
                  type: array
            examples:
              application/json: |
                {
                  "tasks-history": [],
                  "cmd": "/tasks/history/all"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)

        _userCtx = Context.UserContext(login=user_profile['login'])
        if user_profile['administrator']: _userCtx = None
        
        history = TaskManager.instance().getHistory(Full=True, b64=False, user=_userCtx)
        return { "cmd": self.request.path, "tasks-history": history }

class TasksCancel(Handler):
    """
    /rest/tasks/cancel
    """
    @_to_yaml    
    def post(self):
        """
        tags:
          - tasks
        summary: Cancel one specific task according to the id
        description: ''
        operationId: tasksCancel
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ task-id ]
              properties:
                task-id:
                  type: integer
                  description: task id to cancel
        responses:
          '200':
            description: Task successfully cancelled
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "task successfully cancelled",
                  "cmd": "/tasks/cancel"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            taskId = self.request.data.get("task-id")
            if taskId is None: raise EmptyValue("Please specify task-id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input
        if not isinstance(taskId, int):
            raise HTTP_400("Bad task id provided in request, int expected")
        
        _userName = user_profile['login']
        if user_profile['administrator']: _userName = None
        
        # kill all task
        success = TaskManager.instance().cancelTask(taskId=taskId, userName=_userName)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("task id not found")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("access denied to this task")
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("unable to kill the task")

        return { "cmd": self.request.path, "message": "task successfully cancelled", 'task-id': taskId }
        
class TasksCancelSelective(Handler):
    """
    /rest/tasks/cancel/selective
    """
    @_to_yaml    
    def post(self):
        """
        tags:
          - tasks
        summary: Cancel one or more tasks according to the id
        description: ''
        operationId: tasksCancelSelective
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ tasks-id ]
              properties:
                tasks-id:
                  type: array
                  description: list of tasks id to cancel
        responses:
          '200':
            description: Tasks successfully cancelled
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "tasks successfully cancelled",
                  "cmd": "/tasks/cancel/selective"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            tasksId = self.request.data.get("tasks-id")
            if tasksId is None: raise EmptyValue("Please specify tasks-id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input
        if not isinstance(tasksId, list):
            raise HTTP_400("Bad tasks id provided in request, list expected")
        
        _userName = user_profile['login']
        if user_profile['administrator']: _userName = None
        
        # cancel selective tasks
        for taskId in tasksId:
            success = TaskManager.instance().cancelTask(taskId=taskId, userName=_userName)
            if success == Context.instance().CODE_NOT_FOUND:
                raise HTTP_404("task id not found")
            if success == Context.instance().CODE_FORBIDDEN:
                raise HTTP_403("access denied to this task")
            if success == Context.instance().CODE_ERROR:
                raise HTTP_500("unable to cancel the task")

        return { "cmd": self.request.path, "message": "tasks successfully cancelled" }
        
class TasksCancelAll(Handler):
    """
    /rest/tasks/cancel/all
    """
    @_to_yaml    
    def get(self):
        """
        tags:
          - tasks
        summary: Cancel all waiting tasks, only with admin level
        description: ''
        operationId: tasksCancelAll
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: Tasks successfully cancelled
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "tasks successfully cancelled",
                  "cmd": "/tasks/cancel/all"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']:
            raise HTTP_401("Access refused")

        # kill all tasks
        success = TaskManager.instance().cancelAllTasks()

        return { "cmd": self.request.path, "message": "tasks successfully cancelled" }
             
class TasksKill(Handler):
    """
    /rest/tasks/kill
    """
    @_to_yaml    
    def post(self):
        """
        tags:
          - tasks
        summary: Kill one specific task according to the id
        description: ''
        operationId: tasksKill
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ task-id ]
              properties:
                task-id:
                  type: integer
                  description: task id to kill
        responses:
          '200':
            description: Task successfully killed
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "task successfully killed",
                  "cmd": "/tasks/kill"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            taskId = self.request.data.get("task-id")
            if taskId is None: raise EmptyValue("Please specify task-id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input
        if not isinstance(taskId, int):
            raise HTTP_400("Bad task id provided in request, int expected")
        
        _userName = user_profile['login']
        if user_profile['administrator']: _userName = None
        
        # kill all task
        success = TaskManager.instance().killTask(taskId=taskId, userName=_userName)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("task id not found")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("access denied to this task")
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("unable to kill the task")

        return { "cmd": self.request.path, "message": "task successfully killed", 'task-id': taskId }
        
class TasksKillSelective(Handler):
    """
    /rest/tasks/kill/selective
    """
    @_to_yaml    
    def post(self):
        """
        tags:
          - tasks
        summary: Kill one or more tasks according to the id
        description: ''
        operationId: tasksKillSelective
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ tasks-id ]
              properties:
                tasks-id:
                  type: array
                  description: list of tasks id to kill
        responses:
          '200':
            description: Tasks successfully killed
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "tasks successfully killed",
                  "cmd": "/tasks/kill/selective"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            tasksId = self.request.data.get("tasks-id")
            if tasksId is None: raise EmptyValue("Please specify tasks-id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input
        if not isinstance(tasksId, list):
            raise HTTP_400("Bad tasks id provided in request, list expected")
        
        _userName = user_profile['login']
        if user_profile['administrator']: _userName = None
        
        # kill selective tasks
        for taskId in tasksId:
            success = TaskManager.instance().killTask(taskId=taskId, userName=_userName)
            if success == Context.instance().CODE_NOT_FOUND:
                raise HTTP_404("task id not found")
            if success == Context.instance().CODE_FORBIDDEN:
                raise HTTP_403("access denied to this task")
            if success == Context.instance().CODE_ERROR:
                raise HTTP_500("unable to kill the task")

        return { "cmd": self.request.path, "message": "tasks successfully killed" }
        
class TasksKillAll(Handler):
    """
    /rest/tasks/kill/all
    """
    @_to_yaml    
    def get(self):
        """
        tags:
          - tasks
        summary: Kill all running tasks, only with admin level
        description: ''
        operationId: tasksKillAll
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: Tasks successfully killed
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "tasks successfully killed",
                  "cmd": "/tasks/kill/all"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']:
            raise HTTP_401("Access refused")

        # kill all tasks
        success = TaskManager.instance().killAllTasks()

        return { "cmd": self.request.path, "message": "tasks successfully killed" }
        
class TasksHistoryClear(Handler):
    """
    /rest/tasks/history/clear
    """ 
    @_to_yaml
    def get(self):
        """
        tags:
          - tasks
        summary: Reset history tasks, only with admin level
        description: ''
        operationId: tasksHistoryClear
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: History tasks successfully reseted
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "tasks successfully reseted",
                  "cmd": "/tasks/history/clear"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']:
            raise HTTP_401("Access refused")

        success = TaskManager.instance().clearHistory()
        if not success:
            raise HTTP_500("unable to clear the history")
        return { "cmd": self.request.path, "message": "tasks successfully reseted" }
        
class TasksReschedule(Handler):
    """
    /rest/tasks/reschedule
    """ 
    @_to_yaml
    def post(self):
        """
        tags:
          - tasks
        summary: Reschedule a test
        description: ''
        operationId: tasksReschedule
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ task-id, task-enabled, schedule-at, schedule-repeat, probes-enabled, debug-enabled, notifications-enabled, logs-enabled, from-time, to-time  ]
              properties:
                task-id:
                  type: integer
                  description: task id to reschedule
                schedule-id:
                  type: integer
                schedule-type:
                  type: string
                  description: daily | hourly | weekly | every | at | in | now
                task-enabled:
                  type: boolean
                schedule-at:
                  type: array
                  description: [ Y,M,D,H,M,S ]
                schedule-repeat:
                  type: integer
                probes-enabled:
                  type: boolean 
                debug-enabled:
                  type: boolean 
                notifications-enabled:
                  type: boolean 
                logs-enabled:
                  type: boolean 
                from-time:
                  type: array
                  description: [ Y,M,D,H,M,S ]
                to-time:
                  type: array 
                  description: [ Y,M,D,H,M,S ]
        responses:
          '200':
            description: task successfully rescheduled
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "task successfully rescheduled",
                  "cmd": "/tasks/reschedule"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            taskId = self.request.data.get("task-id")
            scheduleType = self.request.data.get("schedule-type")
            scheduleId = self.request.data.get("schedule-id")
            taskEnabled = self.request.data.get("task-enabled")
            scheduleAt = self.request.data.get("schedule-at")
            scheduleRepeat = self.request.data.get("schedule-repeat")
            probesEnabled = self.request.data.get("probes-enabled")
            notificationsEnabled = self.request.data.get("notifications-enabled")
            logsEnabled = self.request.data.get("logs-enabled")
            debugEnabled = self.request.data.get("debug-enabled")
            fromTime = self.request.data.get("from-time")
            toTime = self.request.data.get("to-time")
            
            if taskId is None: raise EmptyValue("Please specify task-id")
            if taskEnabled is None: raise EmptyValue("Please specify task-boolean")
            
            if scheduleType is None and scheduleId is None : raise EmptyValue("Please specify schedule-type or schedule-id")
            if scheduleAt is None: raise EmptyValue("Please specify schedule-at")
            if scheduleRepeat is None: raise EmptyValue("Please specify schedule-repeat")
            
            if probesEnabled is None: raise EmptyValue("Please specify probes-enabled")
            if notificationsEnabled is None: raise EmptyValue("Please specify notifications-enabled")
            if logsEnabled is None: raise EmptyValue("Please specify logs-enabled")
            if debugEnabled is None: raise EmptyValue("Please specify debug-enabled")
            
            if fromTime is None: raise EmptyValue("Please specify from-time")
            if toTime is None: raise EmptyValue("Please specify to-time")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input
        if not isinstance(taskId, int):
            raise HTTP_400("Bad task-id provided in request, int expected")
        if not isinstance(taskEnabled, bool):
            raise HTTP_400("Bad task-enabled provided in request, boolean expected")
        if not isinstance(scheduleRepeat, int):
            raise HTTP_400("Bad schedule-repeat provided in request, int expected")
        if not isinstance(probesEnabled, bool):
            raise HTTP_400("Bad probes-enabled provided in request, boolean expected")
        if not isinstance(notificationsEnabled, bool):
            raise HTTP_400("Bad notifications-enabled provided in request, boolean expected")
        if not isinstance(logsEnabled, bool):
            raise HTTP_400("Bad logs-enabled provided in request, boolean expected")
        if not isinstance(debugEnabled, bool):
            raise HTTP_400("Bad debug-enabled provided in request, boolean expected")
        if len(scheduleAt) != 6:
            raise HTTP_400("Bad schedule-at provided in request, array of size 6 expected")
        if len(fromTime) != 6:
            raise HTTP_400("Bad from-time provided in request, array of size 6 expected")
        if len(toTime) != 6:
            raise HTTP_400("Bad to-time provided in request, array of size 6 expected")
            
        if scheduleType is not None:
            if scheduleType not in TaskManager.SCHEDULE_TYPES:
                raise HTTP_400("Bad schedule-type provided in request, string expected daily | hourly | weekly | every | at | in | now ")
                
        if scheduleId is None:
            scheduleId = TaskManager.SCHEDULE_TYPES[scheduleType]
        
        _userName = user_profile['login']
        if user_profile['administrator']: _userName = None
         
        success = TaskManager.instance().updateTask( taskId = taskId, schedType=scheduleId, schedEnabled=taskEnabled,
                                                    shedAt=scheduleAt, schedNb=scheduleRepeat, withoutProbes=probesEnabled,
                                                    debugActivated=debugEnabled, withoutNotif=notificationsEnabled,
                                                    noKeepTr=logsEnabled, schedFrom=fromTime, schedTo=toTime,
                                                    userName=_userName)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("task id not found")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("access denied to this task")
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("unable to reschedule the task")
            
        return { "cmd": self.request.path, "message": "task successfully rescheduled" }

class TasksVerdict(Handler):
    """
    /rest/tasks/verdict
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tasks
        summary: get the verdict as report of my task
        description: ''
        operationId: tasksVerdict
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ task-id ]
              properties:
                task-id:
                  type: integer
        responses:
          '200':
            description: task replayed with success
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "task replayed with success",
                  "cmd": "/tasks/verdict"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            taskId = self.request.data.get("task-id")
            if taskId is None: raise EmptyValue("Please specify task-id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input
        if not isinstance(taskId, int):
            raise HTTP_400("Bad task id provided in request, int expected")
            
        _userName = user_profile['login']
        if user_profile['administrator']: _userName = None
        
        task = TaskManager.instance().getTaskBy( taskId = taskId, userName=_userName )
        if task == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("task id not found")
        if task == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("access denied to this task")
        
        verdict = task.getTestVerdict()
        xmlVerdict = task.getTestVerdict(returnXml=True)
            
        return { "cmd": self.request.path, "verdict": verdict, "xml-verdict": xmlVerdict }

class TasksReview(Handler):
    """
    /rest/tasks/review
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tasks
        summary: get the review as report of my test
        description: ''
        operationId: tasksReview
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ task-id ]
              properties:
                task-id:
                  type: integer
        responses:
          '200':
            description: task replayed with success
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "task replayed with success",
                  "cmd": "/tasks/review"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            taskId = self.request.data.get("task-id")
            if taskId is None: raise EmptyValue("Please specify task-id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input
        if not isinstance(taskId, int):
            raise HTTP_400("Bad task id provided in request, int expected")
            
        _userName = user_profile['login']
        if user_profile['administrator']: _userName = None
        
        task = TaskManager.instance().getTaskBy( taskId = taskId, userName=_userName )
        if task == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("task id not found")
        if task == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("access denied to this task")
        
        review = task.getTestReport()
        xmlReview = task.getTestReport(returnXml=True)
            
        return { "cmd": self.request.path, "review": review, "xml-review": xmlReview }
        
class TasksDesign(Handler):
    """
    /rest/tasks/design
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tasks
        summary: get the design as report of my task
        description: ''
        operationId: tasksDesign
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ task-id ]
              properties:
                task-id:
                  type: integer
        responses:
          '200':
            description: task replayed with success
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "task replayed with success",
                  "cmd": "/tasks/replay"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            taskId = self.request.data.get("task-id")
            if taskId is None: raise EmptyValue("Please specify task-id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input
        if not isinstance(taskId, int):
            raise HTTP_400("Bad task id provided in request, int expected")
            
        _userName = user_profile['login']
        if user_profile['administrator']: _userName = None
        
        task = TaskManager.instance().getTaskBy( taskId = taskId, userName=_userName )
        if task == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("task id not found")
        if task == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("access denied to this task")
        
        design = task.getTestDesign()
        xmlDesign = task.getTestDesign(returnXml=True)
            
        return { "cmd": self.request.path, "design": design, "xml-design": xmlDesign }
   
class TasksComment(Handler):
    """
    /rest/tasks/comment
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tasks
        summary: add a comment to the task
        description: ''
        operationId: tasksComment
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ task-id, comment, timestamp ]
              properties:
                task-id:
                  type: integer
                comment:
                  type: string
                timestamp:
                  type: string
        responses:
          '200':
            description: task replayed with success
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "comment added with success",
                  "cmd": "/tasks/comment"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            taskId = self.request.data.get("task-id")
            comment = self.request.data.get("comment")
            timestamp = self.request.data.get("timestamp")
            
            if taskId is None: raise EmptyValue("Please specify task-id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input
        if not isinstance(taskId, int):
            raise HTTP_400("Bad task id provided in request, int expected")
            
        _userName = user_profile['login']
        if user_profile['administrator']: _userName = None
        
        task = TaskManager.instance().getTaskBy( taskId = taskId, userName=_userName )
        if task == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("task id not found")
        if task == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("access denied to this task")
        
        archivePath = task.getFileResultPath()
        success, _, _, _ = RepoArchives.instance().addComment(  archiveUser=user_profile['login'], 
                                                                archivePath=archivePath, 
                                                                archivePost=comment, 
                                                                archiveTimestamp=timestamp )
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to add comment")
            
        return { "cmd": self.request.path, "message": "comment added with success" }

class TasksReplay(Handler):
    """
    /rest/tasks/replay
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tasks
        summary: replay my task
        description: ''
        operationId: tastkReplay
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ task-id ]
              properties:
                task-id:
                  type: integer
        responses:
          '200':
            description: task replayed with success
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "task replayed with success",
                  "cmd": "/tasks/replay"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            taskId = self.request.data.get("task-id")
            if taskId is None: raise EmptyValue("Please specify task-id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input
        if not isinstance(taskId, int):
            raise HTTP_400("Bad task id provided in request, int expected")
            
        _userName = user_profile['login']
        if user_profile['administrator']: _userName = None
        
        success = TaskManager.instance().replayTask( tid = taskId, userName=_userName)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("task id not found")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("access denied to this task")
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("unable to replay the task")
            
        return { "cmd": self.request.path, "message": "task replayed with success" }
         
"""
Public storage handlers
"""
class PublicListing(Handler):
    """
    /rest/public/listing
    """   
    def get(self):
        """
        tags:
          - public_storage
        summary: Get the listing of all files and folders in the public area
        description: ''
        operationId: listingPublic
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: Listing file in public area
            schema :
              properties:
                cmd:
                  type: string
                public-listing:
                  type: array
            examples:
              application/json: |
                {
                  "public-listing": [],
                  "cmd": "/public/listing"
                }
          '401':
            description: Access denied 
        """
        user_profile = _get_user(request=self.request)

        listing = RepoPublic.instance().getBasicListing()  
        
        return { "cmd": self.request.path, "public-listing": listing }

class PublicDirectoryAdd(Handler):
    """
    /rest/public/directory/add
    """   
    def post(self):
        """
        tags:
          - public_storage
        summary: Add directory in the public storage
        description: ''
        operationId: addFolderPublic
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ directory-path, directory-name ]
              properties:
                directory-path:
                  type: string
                directory-name:
                  type: string
        responses:
          '200':
            description: Directory successfully added
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "directory successfully added",
                  "cmd": "/public/directory/add"
                }
          '401':
            description: Access denied 
          '400':
            description: Bad request
          '403':
            description: Directory already exists
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            folderName = self.request.data.get("directory-name")
            if not folderName: raise EmptyValue("Please specify a source folder name")
            
            folderPath = self.request.data.get("directory-path")
            if not folderPath: raise EmptyValue("Please specify a source folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        
        success = RepoPublic.instance().addDir(pathFolder=folderPath, folderName=folderName)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to add directory")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully added" } 
        
class PublicDirectoryRename(Handler):
    """
    /rest/public/directory/rename
    """   
    def post(self):
        """
        tags:
          - public_storage
        summary: Rename directory name in the public storage
        description: ''
        operationId: renameFolderPublic
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ directory-path, directory-name ]
                  properties:
                    directory-name:
                      type: string
                    directory-path:
                      type: string
                destination:
                  type: object
                  required: [ directory-name ]
                  properties:
                    directory-name:
                      type: string
        responses:
          '200':
            description: Directory successfully renamed
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "directory successfully renamed",
                  "cmd": "/public/directory/rename"
                }
          '401':
            description: Access denied 
          '400':
            description: Bad request
          '403':
            description: Directory already exists
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
       
        try:
            folderName = self.request.data.get("source")["directory-name"]
            if not folderName: raise EmptyValue("Please specify a source folder name")
            folderPath = self.request.data.get("source")["directory-path"]
            if not folderPath: raise EmptyValue("Please specify a source folder path")
            
            newFolderName = self.request.data.get("destination")["directory-name"]
            if not newFolderName: raise EmptyValue("Please specify a destination folder name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        
        success = RepoTests.instance().renameDir(mainPath=folderPath, oldPath=folderName, 
                                                newPath=newFolderName)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to rename directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to rename directory: source directory not found")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully renamed" }

class PublicDirectoryRemove(Handler):
    """
    /rest/public/directory/remove
    """   
    def post(self):
        """
        tags:
          - public_storage
        summary: Remove directory in the public storage and their contents recursively
        description: ''
        operationId: removeFolderPublic
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source ]
              properties:
                source:
                  type: object
                  required: [ directory-path ]
                  properties:
                    directory-path:
                      type: string
                recursive:
                  type: boolean
        responses:
          '200':
            description: Directory successfully removed
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "directory successfully removed",
                  "cmd": "/public/directory/remove"
                }
          '401':
            description: Access denied 
          '400':
            description: Bad request
          '403':
            description: Cannot remove directory | Removing directory denied
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            folderPath = self.request.data.get("source")["directory-path"]
            if not folderPath: raise EmptyValue("Please specify a source folder path")
            _recursive = self.request.data.get("recursive")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        if _recursive is None:
            recursive = False
        else:
            recursive = _recursive

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        
        if recursive:
            success = RepoTests.instance().delDirAll(folderPath)  
            if success == Context.instance().CODE_ERROR:
                raise HTTP_500("Unable to remove directory")
            if success == Context.instance().CODE_NOT_FOUND:
                raise HTTP_500("Unable to remove directory (missing)")
            if success == Context.instance().CODE_FORBIDDEN:
                raise HTTP_403("Removing directory denied")
        else:
            success = RepoTests.instance().delDir(folderPath)  
            if success == Context.instance().CODE_ERROR:
                raise HTTP_500("Unable to remove directory")
            if success == Context.instance().CODE_NOT_FOUND:
                raise HTTP_500("Unable to remove directory (missing)")
            if success == Context.instance().CODE_FORBIDDEN:
                raise HTTP_403("Cannot remove directory")
                
        return { "cmd": self.request.path, "message": "directory successfully removed" }

class PublicImport(Handler):
    """
    /rest/public/file/import
    """
    def post(self):
        """
        tags:
          - public_storage
        summary: Import file to the public storage. Provide the file in base64 format
        description: ''
        operationId: importFilePublic
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ file-path, file-content ]
              properties:
                file-path:
                  type: string
                file-content:
                  type: string
                  string: in base64 format
        responses:
          '200':
            description: File sucessfully imported
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "file sucessfully imported",
                  "cmd": "/public/file/import"
                }
          '401':
            description: Access denied 
          '400':
            description: Bad request
          '403':
            description: File already exists
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            filePath = self.request.data.get("file-path")
            fileContent = self.request.data.get("file-content")
            if not projectName and not filePath and not fileContent:
                raise EmptyValue("Please specify a project name, file content and path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        _filePath, fileExtension = filePath.rsplit(".", 1)
        _filePath = _filePath.rsplit("/", 1)
        if len(_filePath) == 2:
            filePath = _filePath[0]
            fileName =  _filePath[1]
        else:
            filePath = "/"
            fileName =  _filePath[0]
            
        success, _, _, _, _ = RepoTests.instance().importFile( pathFile=filePath, nameFile=fileName, extFile=fileExtension,
                                                               contentFile=fileContent, binaryMode=True)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to add file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("File already exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully imported" }

class PublicRemove(Handler):
    """
    Remove file from the public storage
    """   
    def post(self):
        """
        Remove file from the public storage
        Send POST request (uri /rest/public/file/remove) with the following body JSON 
        { "file-path": "/" }
        Cookie session_id is mandatory.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            filePath = self.request.data.get("file-path")
            if not projectName and not filePath:
                raise EmptyValue("Please specify a project name and file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success = RepoTests.instance().delFile( pathFile=filePath, supportSnapshot=False)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove file")
        if success == Context.instance().CODE_FAILED:
            raise HTTP_403("Remove file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully removed" }

class PublicRename(Handler):
    """
    Rename file in the public storage
    """
    def post(self):
        """
        Rename file in the public storage
        Send POST request (uri /rest/public/file/rename) with the following body JSON 
            { 
                "source":      {"file-path": "/", "file-name": "test", "file-extension": "tsx"  },
                "destination":  { "file-name": "test" }
            }
        Cookie session_id is mandatory.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            fileName = self.request.data.get("source")["file-path"]
            if not fileName: raise EmptyValue("Please specify a source filename")
            filePath = self.request.data.get("source")["file-name"]
            if not filePath: raise EmptyValue("Please specify a source file path")
            fileExt = self.request.data.get("source")["file-extension"]
            if not fileExt: raise EmptyValue("Please specify a source file extension")
            
            newFileName = self.request.data.get("destination")["file-name"]
            if not newFileName: raise EmptyValue("Please specify a destination file name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success = RepoTests.instance().renameFile( 
                                                    mainPath=filePath, 
                                                    oldFilename=fileName, 
                                                    newFilename=newFileName, 
                                                    extFilename=fileExt,
                                                    supportSnapshot=False
                                                    )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to rename file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Rename file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully renamed" }

class PublicDownload(Handler):
    """
    Download file from the public storage
    """   
    def post(self):
        """
        Download file from the public storage in base64 format
        Send POST request (uri /rest/public/file/download) with the following body JSON { "file-path": "/" }
        Cookie session_id is mandatory.

        @return: file content encoding in base64
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            filePath = self.request.data.get("file-path")
            if not projectName and not filePath:
                raise EmptyValue("Please specify a project name and file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success, _, _, _, content, _, _ = RepoTests.instance().getFile(pathFile=filePath, binaryMode=True, addLock=False)  
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to download file")

        return { "cmd": self.request.path, "file-content": content }

"""
Adapters handler
"""
class AdaptersAdd(Handler):
    """
    /rest/adapters/add
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - adapters
        summary: Add a new adapter
        description: ''
        operationId: adaptersAdd
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                backup-name:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/add", 
                  "message": "added"
                }
          '400':
            description: Bad request provided
          '401':
            description: unauthorized
        """
        user_profile = _get_user(request=self.request)

        try:
            backupName = self.request.data.get("backup-name")
            if backupName is None: 
                raise EmptyValue("Please specify a backupName")            
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success =  RepoLibraries.instance().createBackup(backupName=backupName)  
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to create backup")
            
        return { "cmd": self.request.path, "message": "created" }
  
class AdaptersStatistics(Handler):
    """
    /rest/adapters/statistics
    """   
    @_to_yaml
    def get(self):
        """
        tags:
          - adapters
        summary: get adapters statistics files
        description: ''
        operationId: adaptersStatistics
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: adapters statistics
            schema :
              properties:
                cmd:
                  type: string
                statistics:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/statistics", 
                  "statistics": "...."
                }
        """
        user_profile = _get_user(self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")

        _, _, _, statistics = RepoAdapters.instance().getTree(b64=True)
        
        return { "cmd": self.request.path, "statistics": statistics }

class AdaptersSetDefault(Handler):
    """
    /rest/adapters/set/default
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - adapters
        summary: set adapters as default
        description: ''
        operationId: adaptersSetDefault
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ package-name ]
              properties:
                package-name:
                  type: string
        responses:
          '200':
            description: adapters vXXXX is default
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/set/default", 
                  "message": "success"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        # user_profile = _get_user(self.request)
        
        try:
            packageName = self.request.data.get("package-name")
            if not packageName: raise EmptyValue("Please specify the package name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success =  RepoAdapters.instance().setDefaultV2(packageName)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to set as default the package %s" % packageName )

        return { "cmd": self.request.path, "message": "success" }

class AdaptersSetGeneric(Handler):
    """
    /rest/adapters/set/generic
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - adapters
        summary: set adapters as generic
        description: ''
        operationId: adaptersSetGeneric
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ package-name ]
              properties:
                package-name:
                  type: string
        responses:
          '200':
            description: adapters vXXXX is generic
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/generic", 
                  "message": "success"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(self.request)
        
        try:
            packageName = self.request.data.get("package-name")
            if not packageName: raise EmptyValue("Please specify the package name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success =  RepoAdapters.instance().setGeneric(packageName)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to set as generic the package %s" % packageName )
                
        return { "cmd": self.request.path, "message": "success" }
        
class AdaptersCheckSyntaxAll(Handler):
    """
    /rest/adapters/syntax/all
    """
    @_to_yaml    
    def get(self):
        """
        tags:
          - adapters
        summary: check syntax for all adapters
        description: ''
        operationId: adaptersSyntaxAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: syntax is good
            schema :
              properties:
                cmd:
                  type: string
                syntax-status:
                  type: boolean
                syntax-error:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/syntax/all", 
                  "syntax-status": True,
                  "syntax-error": ""
                }
        """
        user_profile = _get_user(self.request)

        success, details = RepoAdapters.instance().checkGlobalSyntax()
        
        return { "cmd": self.request.path, "syntax-status": success, "syntax-error": details }

class AdaptersFileUnlockAll(Handler):
    """
    /rest/adapters/file/unlock/all
    """   
    @_to_yaml
    def get(self):
        """
        tags:
          - adapters
        summary: unlock all adapters
        description: ''
        operationId: adaptersFileUnlockAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: adapters unlocked
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/file/unlock/all", 
                  "message": "unlocked"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        success = RepoAdapters.instance().cleanupLocks( )
        if not success:
            raise HTTP_500("Unable to unlock all adapters")
            
        return { "cmd": self.request.path, "message": "unlocked" }

class AdaptersBuild(Handler):
    """
    /rest/adapters/build
    """   
    @_to_yaml
    def get(self):
        """
        tags:
          - adapters
        summary: build adapters
        description: ''
        operationId: adaptersBuild
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: adapters packaged
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/build", 
                  "message": "unlocked"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        success = Context.instance().generateAdapters()
        if not success:
            raise HTTP_500("Unable to package adapters")
            
        return { "cmd": self.request.path, "message": "packaged" }
        
class AdaptersBackup(Handler):
    """
    /rest/adapters/backup
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - adapters
        summary: Make a backup of all adapters
        description: ''
        operationId: adaptersBackup
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                backup-name:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/backup", 
                  "message": "created"
                }
          '400':
            description: Bad request provided
          '401':
            description: unauthorized
        """
        user_profile = _get_user(request=self.request)

        try:
            backupName = self.request.data.get("backup-name")
            if backupName is None: 
                raise EmptyValue("Please specify a backupName")            
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success =  RepoAdapters.instance().createBackup(backupName=backupName)  
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to create backup")
            
        return { "cmd": self.request.path, "message": "created" }

class AdaptersBackupDownload(Handler):
    """
    /rest/adapters/backup/download
    """
    @_to_yaml    
    def post(self):
        """
        tags:
          - adapters
        summary: Download backup file
        description: ''
        operationId: adaptersBackupDownload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                backup-name:
                  type: string
                dest-name:
                  type: string 
        responses:
          '200':
            description: backup file
            schema :
              properties:
                cmd:
                  type: string
                backup:
                  type: string
                  description: backup file in base64
                dest-name:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/rest/adapters/backup/download", 
                  "backup": "....",
                  "dest-name": "..."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
        """
        user_profile = _get_user(request=self.request)

        try:
            destName = self.request.data.get("dest-name")
            backupName = self.request.data.get("backup-name")
            if backupName is None: raise EmptyValue("Please specify a backup name")
            if destName is None: raise EmptyValue("Please specify a dest name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success, _, _, _, backupb64, _ = RepoAdapters.instance().getBackup(pathFile=backupName, project='')
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to download backup adapter")
            
        return { "cmd": self.request.path, "backup": backupb64, "dest-name": destName }
        
class AdaptersBackupRemoveAll(Handler):
    """
    /rest/adapters/backup/remove/all
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - adapters
        summary: remove all backups from adapters
        description: ''
        operationId: adaptersBackupRemoveAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/adapters/remove/all", 
                  "message": "deleted"
                }
          '401':
            description: access denied, unauthorized
          '500':
            description: server error
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
          
        success = RepoAdapters.instance().deleteBackups()  
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to delete all backups adapters")
            
        return { "cmd": self.request.path, "message": "deleted" } 

class AdaptersReset(Handler):
    """
    /rest/adapters/reset
    """
    @_to_yaml    
    def get(self):
        """
        tags:
          - adapters
        summary: reset adapters
        description: ''
        operationId: adaptersReset
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: adapters reseted
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/reset", 
                  "message": "reseted"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        success = RepoAdapters.instance().uninstall()
        if not success:
            raise HTTP_500("Unable to reset adapters")
            
        return { "cmd": self.request.path, "message": "reseted" }

class AdaptersBackupListing(Handler):
    """
    /rest/adapters/backup/listing
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - adapters
        summary: return the list of all backups
        description: ''
        operationId: adaptersBackupListing
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                backups:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/backup/listing", 
                  "backups": "..."
                }
          '400':
            description: Bad request provided
          '401':
            description: unauthorized
        """
        user_profile = _get_user(request=self.request)

        backups =  RepoAdapters.instance().getBackups()  

        return { "cmd": self.request.path, "backups": backups }

class AdaptersListing(Handler):
    """
    /rest/adapters/listing
    """   
    @_to_yaml
    def get(self):
        """
        tags:
          - adapters
        summary: Get the listing of all adapters.
        description: ''
        operationId: adaptersListing
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: adapters listing
            schema :
              properties:
                cmd:
                  type: string
                adapters-listing:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/listing", 
                  "adapters-listing": "...."
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        _, _, listing, _ = RepoAdapters.instance().getTree(b64=True)

        return { "cmd": self.request.path, "adapters-listing": listing }
        
class AdaptersFileMove(Handler):
    """
    /rest/adapters/file/move
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - adapters
        summary: Move file
        description: ''
        operationId: adaptersFileMove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ file-name, file-path, file-extension  ]
                  properties:
                    file-name:
                      type: string
                    file-path:
                      type: string
                    file-extension:
                      type: string
                destination:
                  type: object
                  required: [ file-path ]
                  properties:
                    file-path:
                      type: string
        responses:
          '200':
            description: move response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/file/move", 
                  "message": "file successfully moved"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            filePath = self.request.data.get("source")["file-path"]
            if filePath is None: raise EmptyValue("Please specify a source filename")
            fileName = self.request.data.get("source")["file-name"]
            if fileName is None: raise EmptyValue("Please specify a source file path")
            fileExt = self.request.data.get("source")["file-extension"]
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFilePath = self.request.data.get("destination")["file-path"]
            if newFilePath is None: raise EmptyValue("Please specify a destination file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

            
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        newFilePath = os.path.normpath("/" + newFilePath )

        success = RepoAdapters.instance().moveFile( 
                                                        mainPath=filePath, 
                                                        fileName=fileName, 
                                                        extFilename=fileExt, 
                                                        newPath=newFilePath
                                                    )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to move file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Move file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file successfully moved" }
        
class AdaptersDirectoryMove(Handler):
    """
    /rest/adapters/directory/move
    """   
    @_to_yaml   
    def post(self):
        """
        tags:
          - adapters
        summary: Move directory
        description: ''
        operationId: adaptersDirectoryMove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ directory-name, directory-path  ]
                  properties:
                    directory-name:
                      type: string
                    directory-path:
                      type: string
                destination:
                  type: object
                  required: [ directory-path ]
                  properties:
                    directory-path:
                      type: string
        responses:
          '200':
            description: move response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/directory/move", 
                  "message": "directory successfully moved"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        # get the user profile
        user_profile = _get_user(request=self.request)
        
        # checking json request on post
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            folderName = self.request.data.get("source")["directory-name"]
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            folderPath = self.request.data.get("source")["directory-path"]
            if folderPath is None: raise EmptyValue("Please specify a source folder path")

            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFolderPath = self.request.data.get("destination")["directory-path"]
            if newFolderPath is None: raise EmptyValue("Please specify a destination folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # some security check to avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        newFolderPath = os.path.normpath("/" + newFolderPath )
        
        # all ok, do the duplication
        success = RepoAdapters.instance().moveDir(
                                                    mainPath=folderPath, 
                                                    folderName=folderName, 
                                                    newPath=newFolderPath
                                                )  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to move directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to move directory: source directory not found")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully moved"}

class AdaptersFileRename(Handler):
    """
    /rest/adapters/file/rename
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - adapters
        summary: Rename file in the adapters storage 
        description: ''
        operationId: adaptersFileRename
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, file-name, file-path, file-extension  ]
                  properties:
                    project-id:
                      type: integer
                    file-name:
                      type: string
                    file-path:
                      type: string
                    file-extension:
                      type: string
                destination:
                  type: object
                  required: [ project-id, file-name ]
                  properties:
                    project-id:
                      type: integer
                    file-name:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/file/rename", 
                  "message": "file successfully renamed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            fileName = self.request.data.get("source")["file-name"]
            if fileName is None: raise EmptyValue("Please specify a source filename")
            filePath = self.request.data.get("source")["file-path"]
            if filePath is None: raise EmptyValue("Please specify a source file path")
            fileExt = self.request.data.get("source")["file-extension"]
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFileName = self.request.data.get("destination")["file-name"]
            if newFileName is None: raise EmptyValue("Please specify a destination file name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success = RepoAdapters.instance().renameFile( 
                                                    mainPath=filePath, 
                                                    oldFilename=fileName, 
                                                    newFilename=newFileName, 
                                                    extFilename=fileExt
                                                    )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to rename file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Rename file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully renamed",
                 "file-path": filePath,
                 "file-name": fileName,
                 "file-extension": fileExt,
                 "new-file-name": newFileName        }
        
class AdaptersDirectoryRename(Handler):
    """
    /rest/adapters/directory/rename
    """   
    @_to_yaml   
    def post(self):
        """
        tags:
          - adapters
        summary: Rename directory in the adapters storage 
        description: ''
        operationId: adaptersDirectoryRename
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, directory-name, directory-path ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
                    directory-path:
                      type: string
                destination:
                  type: object
                  required: [ project-id, directory-name ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/directory/rename", 
                  "message": "directory successfully renamed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
		
        projectId = None
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            folderName = self.request.data.get("source")["directory-name"]
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            folderPath = self.request.data.get("source")["directory-path"]
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFolderName = self.request.data.get("destination")["directory-name"]
            if newFolderName is None: raise EmptyValue("Please specify a destination folder name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        
        success = RepoAdapters.instance().renameDir(mainPath=folderPath, oldPath=folderName, 
                                                    newPath=newFolderName)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to rename directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to rename directory: source directory not found")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully renamed",
                 "directory-name": folderName, "directory-path": folderPath, 
                 "new-directory-name": newFolderName}

class AdaptersFileDuplicate(Handler):
    """
    /rest/adapters/file/duplicate
    """   
    @_to_yaml    
    def post(self):
        """
        tags:
          - adapters
        summary: Duplicate file in the adapters storage 
        description: ''
        operationId: adaptersFileDuplicate
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, file-name, file-path, file-extension  ]
                  properties:
                    project-id:
                      type: integer
                    file-name:
                      type: string
                    file-path:
                      type: string
                    file-extension:
                      type: string
                destination:
                  type: object
                  required: [ project-id, file-name ]
                  properties:
                    project-id:
                      type: integer
                    file-name:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/file/rename", 
                  "message": "file successfully renamed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            fileName = self.request.data.get("source")["file-name"]
            if fileName is None: raise EmptyValue("Please specify a source filename")
            filePath = self.request.data.get("source")["file-path"]
            if filePath is None: raise EmptyValue("Please specify a source file path")
            fileExt = self.request.data.get("source")["file-extension"]
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFileName = self.request.data.get("destination")["file-name"]
            if newFileName is None: raise EmptyValue("Please specify a destination file name")
            newFilePath = self.request.data.get("destination")["file-path"]
            if newFilePath is None: raise EmptyValue("Please specify a destination file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        newFilePath = os.path.normpath("/" + newFilePath )
        
        success = RepoAdapters.instance().duplicateFile( 
                                                        mainPath=filePath,
                                                        oldFilename=fileName,
                                                        newFilename=newFileName,
                                                        extFilename=fileExt
                                                    )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to duplicate file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Duplicate file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully duplicated" }
        
class AdaptersDirectoryDuplicate(Handler):
    """
    /rest/adapters/directory/duplicate
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - adapters
        summary: Duplicate directory in the adapters storage 
        description: ''
        operationId: adaptersDirectoryDuplicate
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ directory-name, directory-path  ]
                  properties:
                    directory-name:
                      type: string
                    directory-path:
                      type: string
                destination:
                  type: object
                  required: [ directory-name ]
                  properties:
                    directory-name:
                      type: string
                    directory-path:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/directory/rename", 
                  "message": "directory successfully renamed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        # get the user profile
        user_profile = _get_user(request=self.request)
        
        # checking json request on post
        projectId = None
        newProjectId = None
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            folderName = self.request.data.get("source")["directory-name"]
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            folderPath = self.request.data.get("source")["directory-path"]
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFolderName = self.request.data.get("destination")["directory-name"]
            if newFolderName is None: raise EmptyValue("Please specify a destination folder name")
            newFolderPath = self.request.data.get("destination")["directory-path"]
            if newFolderPath is None: raise EmptyValue("Please specify a destination folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # some security check to avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        newFolderPath = os.path.normpath("/" + newFolderPath )
        
        # all ok, do the duplication
        success = RepoAdapters.instance().duplicateDir(
                                                    mainPath=folderPath, 
                                                    oldPath=folderName, 
                                                    newPath=newFolderName,
                                                    newMainPath=newFolderPath
                                                )  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to duplicate directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to duplicate directory: source directory not found")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully duplicated" }

class AdaptersFileRemove(Handler):
    """
    /rest/adapters/file/remove
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - adapters
        summary: remove file in the adapters storage 
        description: ''
        operationId: adaptersFileRemove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ file-path  ]
              properties:
                file-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/file/remove", 
                  "message": "file successfully removed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            filePath = self.request.data.get("file-path")
            if not filePath: raise EmptyValue("Please specify a file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success = RepoAdapters.instance().delFile( pathFile=filePath )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove file")
        if success == Context.instance().CODE_FAILED:
            raise HTTP_403("Remove file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file successfully removed" }

class AdaptersFileUnlock(Handler):
    """
    /rest/adapters/file/unlock
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - adapters
        summary: unlock file in the adapters storage 
        description: ''
        operationId: adaptersFileUnlock
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ file-path, file-name, file-extension  ]
              properties:
                file-path:
                  type: string
                file-name:
                  type: string
                file-extension:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/file/unlock", 
                  "message": "file successfully unlocked"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a source filepath")
            fileName = self.request.data.get("file-name")
            if fileName is None: raise EmptyValue("Please specify a source file filename")
            fileExt = self.request.data.get("file-extension")
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success  = RepoAdapters.instance().unlockFile(pathFile=filePath, 
                                                   nameFile=fileName, 
                                                   extFile=fileExt,
                                                   login=user_profile["login"])
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to unlock adapter file")
            
        return { "cmd": self.request.path, "message": "file successfully unlocked" }

class AdaptersDirectoryRemove(Handler):
    """
    /rest/adapters/directory/remove
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - adapters
        summary: remove directory in the adapters storage 
        description: ''
        operationId: adaptersDirectoryRemove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ directory-path  ]
              properties:
                directory-path:
                  type: string
                recursive:
                  type: boolean
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/directory/remove", 
                  "message": "directory successfully removed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            folderPath = self.request.data.get("directory-path")
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )

        success = RepoAdapters.instance().delDir(folderPath)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to remove directory (missing)")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("Cannot remove directory")
            
        return { "cmd": self.request.path, "message": "directory successfully removed" }
        
class AdaptersDirectoryRemoveAll(Handler):
    """
    /rest/adapters/directory/remove/all
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - adapters
        summary: remove all directories in the adapters storage 
        description: ''
        operationId: adaptersDirectoryRemoveAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ directory-path  ]
              properties:
                directory-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/directory/remove/all", 
                  "message": "all directories successfully removed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            folderPath = self.request.data.get("directory-path")
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        
        success = RepoAdapters.instance().delDirAll(folderPath)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to remove directory (missing)")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("Removing directory denied")
  
        return { "cmd": self.request.path, "message": "all directories successfully removed" }
        
class AdaptersDirectoryAdd(Handler):
    """
    /rest/adapters/directory/add
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - adapters
        summary: Add directory in the adapters storage 
        description: ''
        operationId: adaptersDirectoryAdd
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ directory-name, directory-path ]
              properties:
                directory-name:
                  type: string
                directory-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/directory/add", 
                  "message": "directory successfully added"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            folderName = self.request.data.get("directory-name")
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            
            folderPath = self.request.data.get("directory-path")
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        
        success = RepoAdapters.instance().addDir(pathFolder=folderPath, folderName=folderName)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to add directory")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully added" }

class AdaptersFileUpload(Handler):
    """
    /rest/adapters/file/upload
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - adapters
        summary: Upload file the test storage 
        description: ''
        operationId: adaptersFileUpload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, directory-name, directory-path ]
              properties:
                project-id:
                  type: integer
                directory-name:
                  type: string
                directory-path:
                  type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/directory/rename", 
                  "message": "directory successfully renamed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
            
            filePath = self.request.data.get("file-path")
            fileContent = self.request.data.get("file-content")
            if not filePath and not fileContent: raise EmptyValue("Please specify a file content and path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        _filePath, fileExtension = filePath.rsplit(".", 1)
        _filePath = _filePath.rsplit("/", 1)
        if len(_filePath) == 2:
            filePath = _filePath[0]
            fileName =  _filePath[1]
        else:
            filePath = "/"
            fileName =  _filePath[0]
            
        success, _, _, _, _ = RepoTests.instance().importFile( pathFile=filePath, nameFile=fileName, extFile=fileExtension,
                                                                                contentFile=fileContent, binaryMode=True, project=prjId)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to add file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("File already exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully imported" }

class AdaptersFileDownload(Handler):
    """
    /rest/adapters/file/download
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - adapters
        summary: download file from the test storage 
        description: ''
        operationId: adaptersFileDownload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, file-path ]
              properties:
                project-id:
                  type: integer
                file-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                file-content:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/file/download", 
                  "file-content": "...."
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a  project id")
            
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success, _, _, _, content, _, _ = RepoTests.instance().getFile(pathFile=filePath, 
                                                                       binaryMode=True, 
                                                                       project=projectId, 
                                                                       addLock=False)  
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to download file")

        return { "cmd": self.request.path, "file-content": content }
        
class AdaptersFileOpen(Handler):
    """
    /rest/adapters/file/open
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - adapters
        summary: open and lock file from the test storage 
        description: ''
        operationId: adaptersFileOpen
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, file-path ]
              properties:
                project-id:
                  type: integer
                file-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                file-content:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/adapters/file/open", 
                  "file-content": "...."
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a file path")
            
            _ignoreLock = self.request.data.get("ignore-lock")
            _readOnly = self.request.data.get("read-only")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        ignoreLock = False
        if _ignoreLock is not None:
            ignoreLock = _ignoreLock
        
        readOnly = False
        if _readOnly is not None:
            _readOnly = readOnly
           
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )

        resultGetFile = RepoAdapters.instance().getFile(pathFile=filePath, 
                                                        login=user_profile['login'],
                                                        forceOpen=ignoreLock, 
                                                        readOnly=readOnly)  
        success, path_file, name_file, ext_file, project, data_base64, locked, locked_by = resultGetFile 
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to open adapter file")

        return { "cmd": self.request.path, 
                 "file-content": data_base64,
                 "file-path": path_file,
                 "file-name": name_file,
                 "file-extension": ext_file,
                 "locked": locked,
                 "locked-by": locked_by,
                 "project-id": project }
        
"""
Libraries handler
"""
class LibrariesAdd(Handler):
    """
    /rest/libraries/add
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - libraries
        summary: Add a new library
        description: ''
        operationId: librariesAdd
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                backup-name:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/add", 
                  "message": "added"
                }
          '400':
            description: Bad request provided
          '401':
            description: unauthorized
        """
        user_profile = _get_user(request=self.request)

        try:
            backupName = self.request.data.get("backup-name")
            if backupName is None: 
                raise EmptyValue("Please specify a backupName")            
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success =  RepoLibraries.instance().createBackup(backupName=backupName)  
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to create backup")
            
        return { "cmd": self.request.path, "message": "created" }
             
class LibrariesStatistics(Handler):
    """
    /rest/libraries/statistics
    """   
    @_to_yaml
    def get(self):
        """
        tags:
          - libraries
        summary: get libraries statistics files
        description: ''
        operationId: librariesStatistics
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: libraries statistics
            schema :
              properties:
                cmd:
                  type: string
                statistics:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/statistics", 
                  "statistics": "...."
                }
        """
        user_profile = _get_user(self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")

        _, _, _, statistics = RepoLibraries.instance().getTree(b64=True)
        
        return { "cmd": self.request.path, "statistics": statistics }

class LibrariesSetDefault(Handler):
    """
    /rest/libraries/set/default
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - libraries
        summary: set libraries as default
        description: ''
        operationId: librariesSetDefault
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ package-name ]
              properties:
                package-name:
                  type: string
        responses:
          '200':
            description: libraries packaged
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/set/default", 
                  "message": "success"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(self.request)
        
        try:
            packageName = self.request.data.get("package-name")
            if not packageName: raise EmptyValue("Please specify the package name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success =  RepoLibraries.instance().setDefaultV2(packageName)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to set as default the package %s" % packageName )

        return { "cmd": self.request.path, "message": "success"  }

class LibrariesSetGeneric(Handler):
    """
    /rest/libraries/set/generic
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - libraries
        summary: set libraries as generic
        description: ''
        operationId: librariesSetGeneric
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ package-name ]
              properties:
                package-name:
                  type: string
        responses:
          '200':
            description: libraries packaged
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/set/generic", 
                  "message": "success"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error 
        """
        user_profile = _get_user(self.request)
        
        try:
            packageName = self.request.data.get("package-name")
            if not packageName: raise EmptyValue("Please specify the package name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success =  RepoLibraries.instance().setGeneric(packageName)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to set as generic the package %s" % packageName )
                
        return { "cmd": self.request.path, "message": "success"  }
        
class LibrariesCheckSyntaxAll(Handler):
    """
    /rest/libraries/syntax/all
    """   
    @_to_yaml   
    def get(self):
        """
        tags:
          - libraries
        summary: check syntax for all libraries
        description: ''
        operationId: librariesSyntaxAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: syntax is good
            schema :
              properties:
                cmd:
                  type: string
                syntax-status:
                  type: boolean
                syntax-error:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/syntax/all", 
                  "syntax-status": True,
                  "syntax-error": ""
                }
        """
        user_profile = _get_user(self.request)

        success, details = RepoLibraries.instance().checkGlobalSyntax()
        
        return { "cmd": self.request.path, "syntax-status": success, "syntax-error": details }

class LibrariesFileUnlockAll(Handler):
    """
    /rest/libraries/file/unlock/all
    """   
    @_to_yaml
    def get(self):
        """
        tags:
          - libraries
        summary: unlock all libraries
        description: ''
        operationId: librariesFileUnlockAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: libraries unlocked
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/file/unlock/all", 
                  "message": "unlocked"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        success = RepoLibraries.instance().cleanupLocks( )
        if not success:
            raise HTTP_500("Unable to unlock all libraries")
            
        return { "cmd": self.request.path, "message": "unlocked" }

class LibrariesBuild(Handler):
    """
    /rest/libraries/build
    """   
    @_to_yaml
    def get(self):
        """
        tags:
          - libraries
        summary: build libraries
        description: ''
        operationId: librariesBuild
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: libraries packaged
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/build", 
                  "message": "unlocked"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        success = Context.instance().generateLibraries()
        if not success:
            raise HTTP_500("Unable to package libraries")
            
        return { "cmd": self.request.path, "message": "packaged" }

class LibrariesBackup(Handler):
    """
    /rest/libraries/backup
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - libraries
        summary: Make a backup of all libraries
        description: ''
        operationId: librariesBackup
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                backup-name:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/backup", 
                  "message": "created"
                }
          '400':
            description: Bad request provided
          '401':
            description: unauthorized
        """
        user_profile = _get_user(request=self.request)

        try:
            backupName = self.request.data.get("backup-name")
            if backupName is None: 
                raise EmptyValue("Please specify a backupName")            
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success =  RepoLibraries.instance().createBackup(backupName=backupName)  
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to create backup")
            
        return { "cmd": self.request.path, "message": "created" }
         
class LibrariesBackupDownload(Handler):
    """
    /rest/libraries/backup/download
    """
    @_to_yaml    
    def post(self):
        """
        tags:
          - libraries
        summary: Download backup file
        description: ''
        operationId: librariesBackupDownload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                backup-name:
                  type: string
                dest-name:
                  type: string 
        responses:
          '200':
            description: backup file
            schema :
              properties:
                cmd:
                  type: string
                backup:
                  type: string
                  description: backup file in base64
                dest-name:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/rest/libraries/backup/download", 
                  "backup": "....",
                  "dest-name": "..."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
        """
        user_profile = _get_user(request=self.request)

        try:
            destName = self.request.data.get("dest-name")
            backupName = self.request.data.get("backup-name")
            if backupName is None: raise EmptyValue("Please specify a backup name")
            if destName is None: raise EmptyValue("Please specify a dest name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success, _, _, _, backupb64, _ = RepoLibraries.instance().getBackup(pathFile=backupName, project='')
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to download backup library")
            
        return { "cmd": self.request.path, "backup": backupb64, "dest-name": destName }
        
class LibrariesBackupRemoveAll(Handler):
    """
    /rest/libraries/backup/remove/all
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - libraries
        summary: remove all backups from libraries
        description: ''
        operationId: librariesBackupRemoveAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/libraries/remove/all", 
                  "message": "deleted"
                }
          '401':
            description: access denied, unauthorized
          '500':
            description: server error
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        success = RepoLibraries.instance().deleteBackups()  
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to delete all backups libraries")
            
        return { "cmd": self.request.path, "message": "deleted" } 
        
class LibrariesReset(Handler):
    """
    /rest/libraries/reset
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - libraries
        summary: reset libraries
        description: ''
        operationId: librariesReset
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: libraries reseted
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/reset", 
                  "message": "reseted"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        success = RepoLibraries.instance().uninstall()
        if not success:
            raise HTTP_500("Unable to reset libraries")
            
        return { "cmd": self.request.path, "message": "reseted" }

class LibrariesBackupListing(Handler):
    """
    /rest/libraries/backup/listing
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - libraries
        summary: return the list of all backups
        description: ''
        operationId: librariesBackupListing
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                backups:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/backup/listing", 
                  "backups": "..."
                }
          '400':
            description: Bad request provided
          '401':
            description: unauthorized
        """
        user_profile = _get_user(request=self.request)

        backups =  RepoLibraries.instance().getBackups()  

        return { "cmd": self.request.path, "backups": backups }

class LibrariesListing(Handler):
    """
    /rest/libraries/listing
    """   
    @_to_yaml
    def get(self):
        """
        tags:
          - libraries
        summary: Get the listing of all libraries.
        description: ''
        operationId: librariesListing
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: libraries listing
            schema :
              properties:
                cmd:
                  type: string
                libraries-listing:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/listing", 
                  "libraries-listing": "...."
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        _, _, listing, _ = RepoLibraries.instance().getTree(b64=True)

        return { "cmd": self.request.path, "libraries-listing": listing }
        
class LibrariesFileMove(Handler):
    """
    /rest/libraries/file/move
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - libraries
        summary: Move file
        description: ''
        operationId: librariesFileMove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ file-name, file-path, file-extension  ]
                  properties:
                    file-name:
                      type: string
                    file-path:
                      type: string
                    file-extension:
                      type: string
                destination:
                  type: object
                  required: [ file-path ]
                  properties:
                    file-path:
                      type: string
        responses:
          '200':
            description: move response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/file/move", 
                  "message": "file successfully moved"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            filePath = self.request.data.get("source")["file-path"]
            if filePath is None: raise EmptyValue("Please specify a source filename")
            fileName = self.request.data.get("source")["file-name"]
            if fileName is None: raise EmptyValue("Please specify a source file path")
            fileExt = self.request.data.get("source")["file-extension"]
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFilePath = self.request.data.get("destination")["file-path"]
            if newFilePath is None: raise EmptyValue("Please specify a destination file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        newFilePath = os.path.normpath("/" + newFilePath )
        
        success = RepoLibraries.instance().moveFile( 
                                                        mainPath=filePath, 
                                                        fileName=fileName, 
                                                        extFilename=fileExt, 
                                                        newPath=newFilePath
                                                    )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to move file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Move file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file successfully moved" }
        
class LibrariesDirectoryMove(Handler):
    """
    /rest/libraries/directory/move
    """   
    @_to_yaml   
    def post(self):
        """
        tags:
          - libraries
        summary: Move directory
        description: ''
        operationId: librariesDirectoryMove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ directory-name, directory-path  ]
                  properties:
                    directory-name:
                      type: string
                    directory-path:
                      type: string
                destination:
                  type: object
                  required: [ directory-path ]
                  properties:
                    directory-path:
                      type: string
        responses:
          '200':
            description: move response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/directory/move", 
                  "message": "directory successfully moved"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        # get the user profile
        user_profile = _get_user(request=self.request)
        
        # checking json request on post
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            folderName = self.request.data.get("source")["directory-name"]
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            folderPath = self.request.data.get("source")["directory-path"]
            if folderPath is None: raise EmptyValue("Please specify a source folder path")

            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFolderPath = self.request.data.get("destination")["directory-path"]
            if newFolderPath is None: raise EmptyValue("Please specify a destination folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # some security check to avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        newFolderPath = os.path.normpath("/" + newFolderPath )
        
        # all ok, do the duplication
        success = RepoLibraries.instance().moveDir(
                                                    mainPath=folderPath, 
                                                    folderName=folderName, 
                                                    newPath=newFolderPath
                                                )  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to move directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to move directory: source directory not found")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully moved"}

class LibrariesFileRename(Handler):
    """
    /rest/libraries/file/rename
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - libraries
        summary: Rename file in the libraries storage 
        description: ''
        operationId: librariesFileRename
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, file-name, file-path, file-extension  ]
                  properties:
                    project-id:
                      type: integer
                    file-name:
                      type: string
                    file-path:
                      type: string
                    file-extension:
                      type: string
                destination:
                  type: object
                  required: [ project-id, file-name ]
                  properties:
                    project-id:
                      type: integer
                    file-name:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/file/rename", 
                  "message": "file successfully renamed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            fileName = self.request.data.get("source")["file-name"]
            if fileName is None: raise EmptyValue("Please specify a source filename")
            filePath = self.request.data.get("source")["file-path"]
            if filePath is None: raise EmptyValue("Please specify a source file path")
            fileExt = self.request.data.get("source")["file-extension"]
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFileName = self.request.data.get("destination")["file-name"]
            if newFileName is None: raise EmptyValue("Please specify a destination file name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success = RepoLibraries.instance().renameFile( 
                                                    mainPath=filePath, 
                                                    oldFilename=fileName, 
                                                    newFilename=newFileName, 
                                                    extFilename=fileExt
                                                    )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to rename file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Rename file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully renamed",
                 "file-path": filePath,
                 "file-name": fileName,
                 "file-extension": fileExt,
                 "new-file-name": newFileName}
        
class LibrariesDirectoryRename(Handler):
    """
    /rest/libraries/directory/rename
    """   
    @_to_yaml   
    def post(self):
        """
        tags:
          - libraries
        summary: Rename directory in the libraries storage 
        description: ''
        operationId: librariesDirectoryRename
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, directory-name, directory-path ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
                    directory-path:
                      type: string
                destination:
                  type: object
                  required: [ project-id, directory-name ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/directory/rename", 
                  "message": "directory successfully renamed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
		
        projectId = None
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            folderName = self.request.data.get("source")["directory-name"]
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            folderPath = self.request.data.get("source")["directory-path"]
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFolderName = self.request.data.get("destination")["directory-name"]
            if newFolderName is None: raise EmptyValue("Please specify a destination folder name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        
        success = RepoLibraries.instance().renameDir(mainPath=folderPath, oldPath=folderName, 
                                                    newPath=newFolderName)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to rename directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to rename directory: source directory not found")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully renamed",
                 "directory-name": folderName, "directory-path": folderPath, 
                 "new-directory-name": newFolderName}

class LibrariesFileDuplicate(Handler):
    """
    /rest/libraries/file/duplicate
    """   
    @_to_yaml    
    def post(self):
        """
        tags:
          - libraries
        summary: Duplicate file in the libraries storage 
        description: ''
        operationId: librariesFileDuplicate
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ file-name, file-path, file-extension  ]
                  properties:
                    file-name:
                      type: string
                    file-path:
                      type: string
                    file-extension:
                      type: string
                destination:
                  type: object
                  required: [ file-name ]
                  properties:
                    file-name:
                      type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/file/duplicate", 
                  "message": "file successfully renamed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            fileName = self.request.data.get("source")["file-name"]
            if fileName is None: raise EmptyValue("Please specify a source filename")
            filePath = self.request.data.get("source")["file-path"]
            if filePath is None: raise EmptyValue("Please specify a source file path")
            fileExt = self.request.data.get("source")["file-extension"]
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFileName = self.request.data.get("destination")["file-name"]
            if newFileName is None: raise EmptyValue("Please specify a destination file name")
            newFilePath = self.request.data.get("destination")["file-path"]
            if newFilePath is None: raise EmptyValue("Please specify a destination file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        newFilePath = os.path.normpath("/" + newFilePath )
        
        success = RepoLibraries.instance().duplicateFile( 
                                                        mainPath=filePath,
                                                        oldFilename=fileName,
                                                        newFilename=newFileName,
                                                        extFilename=fileExt
                                                    )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to duplicate file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Duplicate file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully duplicated" }
        
class LibrariesDirectoryDuplicate(Handler):
    """
    /rest/libraries/directory/duplicate
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - libraries
        summary: Duplicate directory in the libraries storage 
        description: ''
        operationId: librariesDirectoryDuplicate
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ directory-name, directory-path ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
                    directory-path:
                      type: string
                destination:
                  type: object
                  required: [ directory-name, directory-path ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
                    directory-path:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/directory/rename", 
                  "message": "directory successfully renamed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        # get the user profile
        user_profile = _get_user(request=self.request)
        
        # checking json request on post
        projectId = None
        newProjectId = None
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            folderName = self.request.data.get("source")["directory-name"]
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            folderPath = self.request.data.get("source")["directory-path"]
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newFolderName = self.request.data.get("destination")["directory-name"]
            if newFolderName is None: raise EmptyValue("Please specify a destination folder name")
            newFolderPath = self.request.data.get("destination")["directory-path"]
            if newFolderPath is None: raise EmptyValue("Please specify a destination folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # some security check to avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        newFolderPath = os.path.normpath("/" + newFolderPath )
        
        # all ok, do the duplication
        success = RepoLibraries.instance().duplicateDir(
                                                    mainPath=folderPath, 
                                                    oldPath=folderName, 
                                                    newPath=newFolderName,
                                                    newMainPath=newFolderPath
                                                )  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to duplicate directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to duplicate directory: source directory not found")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully duplicated" }

class LibrariesFileRemove(Handler):
    """
    /rest/libraries/file/remove
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - libraries
        summary: remove file in the libraries storage 
        description: ''
        operationId: librariesFileRemove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ file-path  ]
              properties:
                file-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/file/remove", 
                  "message": "file successfully removed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success = RepoLibraries.instance().delFile( pathFile=filePath )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove file")
        if success == Context.instance().CODE_FAILED:
            raise HTTP_403("Remove file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file successfully removed" }
        
class LibrariesFileUnlock(Handler):
    """
    /rest/libraries/file/unlock
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - libraries
        summary: unlock file in the libraries storage 
        description: ''
        operationId: librariesFileUnlock
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ file-path, file-name, file-extension  ]
              properties:
                file-path:
                  type: string
                file-name:
                  type: string
                file-extension:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/file/unlock", 
                  "message": "file successfully unlocked"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a source filepath")
            fileName = self.request.data.get("file-name")
            if fileName is None: raise EmptyValue("Please specify a source file filename")
            fileExt = self.request.data.get("file-extension")
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success  = RepoLibraries.instance().unlockFile(pathFile=filePath, 
                                                       nameFile=fileName, 
                                                       extFile=fileExt,
                                                       login=user_profile["login"])
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to unlock library file")
            
        return { "cmd": self.request.path, "message": "file successfully unlocked" }

class LibrariesDirectoryRemove(Handler):
    """
    /rest/libraries/directory/remove
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - libraries
        summary: remove directory in the libraries storage 
        description: ''
        operationId: librariesDirectoryRemove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ directory-path  ]
              properties:
                directory-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/directory/remove", 
                  "message": "directory successfully removed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            folderPath = self.request.data.get("directory-path")
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )

        success = RepoLibraries.instance().delDir(folderPath)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to remove directory (missing)")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("Cannot remove directory")
                
        return { "cmd": self.request.path, "message": "directory successfully removed" }

class LibrariesDirectoryRemoveAll(Handler):
    """
    /rest/libraries/directory/remove/all
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - libraries
        summary: remove all directories in the libraries storage 
        description: ''
        operationId: librariesDirectoryRemoveAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ directory-path  ]
              properties:
                directory-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/directory/remove/all", 
                  "message": "all directories successfully removed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            folderPath = self.request.data.get("directory-path")
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )

        success = RepoLibraries.instance().delDirAll(folderPath)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to remove directory (missing)")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("Removing directory denied")
            
        return { "cmd": self.request.path, "message": "all directories successfully removed" }

class LibrariesDirectoryAdd(Handler):
    """
    /rest/libraries/directory/add
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - libraries
        summary: Add directory in the libraries storage 
        description: ''
        operationId: librariesDirectoryAdd
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ directory-name, directory-path ]
              properties:
                directory-name:
                  type: string
                directory-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/directory/add", 
                  "message": "directory successfully added"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            folderName = self.request.data.get("directory-name")
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            
            folderPath = self.request.data.get("directory-path")
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        
        success = RepoLibraries.instance().addDir(pathFolder=folderPath, folderName=folderName)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to add directory")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully added" }

class LibrariesFileUpload(Handler):
    """
    /rest/libraries/file/upload
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - libraries
        summary: Upload file the test storage 
        description: ''
        operationId: librariesFileUpload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, directory-name, directory-path ]
              properties:
                project-id:
                  type: integer
                directory-name:
                  type: string
                directory-path:
                  type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/directory/rename", 
                  "message": "directory successfully renamed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
            
            filePath = self.request.data.get("file-path")
            fileContent = self.request.data.get("file-content")
            if not filePath and not fileContent: raise EmptyValue("Please specify a file content and path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        _filePath, fileExtension = filePath.rsplit(".", 1)
        _filePath = _filePath.rsplit("/", 1)
        if len(_filePath) == 2:
            filePath = _filePath[0]
            fileName =  _filePath[1]
        else:
            filePath = "/"
            fileName =  _filePath[0]
            
        success, _, _, _, _ = RepoTests.instance().importFile( pathFile=filePath, nameFile=fileName, extFile=fileExtension,
                                                                                contentFile=fileContent, binaryMode=True, project=prjId)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to add file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("File already exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully imported" }

class LibrariesFileDownload(Handler):
    """
    /rest/libraries/file/download
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - libraries
        summary: download file from the test storage 
        description: ''
        operationId: librariesFileDownload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, file-path ]
              properties:
                project-id:
                  type: integer
                file-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                file-content:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/file/download", 
                  "file-content": "...."
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a  project id")
            
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success, _, _, _, content, _, _ = RepoTests.instance().getFile(pathFile=filePath, 
                                                                       binaryMode=True, 
                                                                       project=projectId, 
                                                                       addLock=False)  
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to download file")

        return { "cmd": self.request.path, "file-content": content }
        
class LibrariesFileOpen(Handler):
    """
    /rest/libraries/file/open
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - libraries
        summary: open and lock file from the test storage 
        description: ''
        operationId: librariesFileOpen
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, file-path ]
              properties:
                project-id:
                  type: integer
                file-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                file-content:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/libraries/file/open", 
                  "file-content": "...."
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a file path")
            
            _ignoreLock = self.request.data.get("ignore-lock")
            _readOnly = self.request.data.get("read-only")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        ignoreLock = False
        if _ignoreLock is not None:
            ignoreLock = _ignoreLock
        
        readOnly = False
        if _readOnly is not None:
            _readOnly = readOnly
            
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )

        resultGetFile = RepoLibraries.instance().getFile(pathFile=filePath,  
                                                        login=user_profile['login'],
                                                        forceOpen=ignoreLock,
                                                        readOnly=readOnly)
        success, path_file, name_file, ext_file, project, data_base64, locked, locked_by = resultGetFile
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to open library file")

        return { "cmd": self.request.path, 
                 "file-content": data_base64,
                 "file-path": path_file,
                 "file-name": name_file,
                 "file-extension": ext_file,
                 "locked": locked,
                 "locked-by": locked_by,
                 "project-id": project }

"""
Documentations handler
"""     
class DocumentationsCache(Handler):
    """
    /rest/documentations/cache
    """   
    @_to_yaml   
    def get(self):
        """
        tags:
          - documentations
        summary: get documentations from cache
        description: ''
        operationId: documentationsCache
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: usages
            schema :
              properties:
                cmd:
                  type: string
            examples:
              application/json: |
                {
                  "cache": "....",
                  "cmd": "/documentations/cache"
                }
          '401':
            description: Access denied
        """
        user_profile = _get_user(self.request)

        docs = {}
        docs["help"] = HelperManager.instance().getHelps()
        
        return { "cmd": self.request.path, "cache": docs }
        
class DocumentationsBuild(Handler):
    """
    /rest/documentations/build
    """
    @_to_yaml    
    def get(self):
        """
        tags:
          - documentations
        summary: build a cache for the documentations
        description: ''
        operationId: documentationsBuild
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: usages
            schema :
              properties:
                cmd:
                  type: string
            examples:
              application/json: |
                {
                  "build": "success",
                  "cmd": "/documentations/build"
                }
          '401':
            description: Access denied
        """
        user_profile = _get_user(self.request)

        success, details = HelperManager.instance().generateHelps()

        return { "cmd": self.request.path, "build": success, "details": details }
        
"""
Tests handlers
"""
class TestsRun(Handler):
    """
    /rest/tests/run
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - tests
        summary: Run one test according to the project name and the path, name and extension of the test. 
        description: ''
        operationId: testsRun
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, test-path ]
              properties:
                test-path:
                  type: string
                project-id:
                  type: integer
                test-inputs:
                  type: array
                  description: Test inputs parameters can be used to overwrite the original test parameters
                  items:
                    type: object
                    required: [ name, value, type ]
                    properties:
                      name:
                        type: string
                      type:
                        type: string
                      value:
                        type: string
                test-outputs:
                  type: array
                  description: Test outputs parameters can be used to overwrite the original test parameters
                  items:
                    type: object
                    required: [ name, value, type ]
                    properties:
                      name:
                        type: string
                      type:
                        type: string
                      value:
                        type: string
                test-adapters:
                  type: string
                  description: adapters options can be used to select the adapters or libraries
                test-librairies:
                  type: string
                  description: libraries options can be used to select the adapters or libraries
                test-agents:
                  type: array
                  description: agents parameters can be used to overwrite the original test
                  items:
                    type: object
                    required: [ name, value, type ]
                    properties:
                      name:
                        type: string
                      type:
                        type: string
                      value:
                        type: string
                number-occurences:
                  type: integer
                  description: Specify the number of occurences to execute your test several times in successive mode
                schedule:
                  description: Schedule your run    
                  type: object
                  required: [ at, type ]
                  properties:
                    at:
                      type: array
                      description: (year, month, day,hours,minutes,seconds)
                    type:
                      type: string
                      description: weekly/daily/hourly/every/min/at/in
                testcfg-inputs:
                  description: Test config file can be used to provide test parameters
                  type: object
                  required: [ project-name, testcfg-path ]
                  properties:
                    project-name:
                      type: string
                    testcfg-path:
                      type: string
                testcfg-outputs:
                  description: Test config file can be used to provide test parameters
                  type: object
                  required: [ project-name, testcfg-path ]
                  properties:
                    project-name:
                      type: string
                    testcfg-path:
                      type: string
        responses:
          '200':
            description: test executed
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                test-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/run", 
                  "message": "test executed"
                  "test-id": "bd0df6b4-10df-4a57-a970-8d693ddb4cfa"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project | Test extension not accepted
          '404':
            description: Test does not exists in repository
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
            
            testPath = self.request.data.get("test-path")
            testInputs = self.request.data.get("test-inputs")
            testOutputs = self.request.data.get("test-outputs")
            sutAdapters = self.request.data.get("test-adapters")
            sutLibraries = self.request.data.get("test-libraries")
            testAgents = self.request.data.get("test-agents")

            numberRuns = self.request.data.get("number-occurences")
            schedule = self.request.data.get("schedule")
            
            testcfgInputs = self.request.data.get("testcfg-inputs")
            testcfgOutputs = self.request.data.get("testcfg-outputs")
            
            if not testPath: raise EmptyValue("Please specify a project name and test path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # check if the file exists
        if not os.path.isfile( "%s/%s/%s" % (RepoTests.instance().testsPath, prjId, testPath) ):
            raise HTTP_404('Test does not exists in repository')
        
        # extract test name and test extension
        testExtension = testPath.rsplit(".", 1)[1]
        testName = "/%s" % testPath
        testName = testName.rsplit("/", 1)[1].rsplit(".", 1)[0]
        
        # checking schedule
        runNb = -1; runType=-1;
        runAt = (0,0,0,0,0,0)
        if numberRuns is not None:
            if not isinstance(numberRuns, int):
                raise HTTP_400("Bad number runs in request, integer expected")
            if numberRuns < 1:
                raise HTTP_400("Bad number runs in request, must be greater to 1")
            if numberRuns > 1:
                runNb = numberRuns; runType = 8; # successive mode 
        if schedule is not None:
            if not isinstance(schedule, dict):
                raise HTTP_400("Bad schedule in request, dict expected")
            if "at" not in schedule:
                raise HTTP_400("At is missing in request")
            if "type" not in schedule:
                raise HTTP_400("Type is missing in request")
            if schedule["type"] in [ "weekly", "daily", "hourly", "every", "min", "at", "in" ]:
                raise HTTP_400("Bad type value in request")
            if not isinstance(schedule["at"], tuple):
                raise HTTP_400("Bad at type in request, tuple expected")
            if len(schedule["at"]) != 6:
                raise HTTP_400("Bad at tuple in request, tuple of 6 integers expected")
            
            if schedule["type"] == "weekly": runType = 7
            if schedule["type"] == "daily": runType = 5
            if schedule["type"] == "hourly": runType = 4
            if schedule["type"] == "every": runType = 6
            if schedule["type"] == "min": runType = 3
            if schedule["type"] == "at": runType = 0
            if schedule["type"] == "in": runType = 1
            
            runAt = schedule["at"]
            
        # checking test inputs, adapters and libraries type
        if testInputs is not None:
            if not isinstance(testInputs, list): 
                raise HTTP_400("Bad test inputs provided in request, list expected")
            for inp in testInputs:
                if not isinstance(inp, dict):     
                    raise HTTP_400("Bad test inputs provided in request, list of dict expected")
                if not ( "name" in inp and "type" in inp and "value" in inp ):
                    raise HTTP_400("Bad test format inputs provided in request")
                    
        if testOutputs is not None:
            if not isinstance(testOutputs, list): 
                raise HTTP_400("Bad test outputs provided in request, list expected")
            for out in testOutputs:
                if not isinstance(out, dict):     
                    raise HTTP_400("Bad test outputs provided in request, list of dict expected")
                if not ( "name" in out and "type" in out and "value" in out ):
                    raise HTTP_400("Bad test format outputs provided in request")
                    
        if testAgents is not None:
            if not isinstance(testAgents, list): 
                raise HTTP_400("Bad test agents provided in request, list expected")
            for agt in testAgents:
                if not isinstance(agt, dict):     
                    raise HTTP_400("Bad test agents provided in request, list of dict expected")
                if not ( "name" in agt and "type" in agt and "value" in agt ):
                    raise HTTP_400("Bad test format agents provided in request")

        if sutAdapters is not None:
            if not isinstance(sutAdapters, str): 
                raise HTTP_400("Bad sut adapter provided in request, str expected")
        
        if sutLibraries is not None:
            if not isinstance(sutLibraries, str): 
                raise HTTP_400("Bad sut library provided in request, str expected")
              
        if testcfgInputs is not None:
            if not isinstance(testcfgInputs, dict): 
                raise HTTP_400("Bad test config inputs provided in request, dict expected")
            if not ( "project-name" in testcfgInputs and "testcfg-path" in testcfgInputs ) :
                raise HTTP_400("Bad test config inputs provided in request, dict expected with project name and path")
            
            if not testcfgInputs["testcfg-path"].endswith(".tcx"):
                raise HTTP_400('Tcx file required for test config inputs')
                
            # get the project id according to the name and checking authorization
            projectcfgId = ProjectsManager.instance().getProjectID(name=testcfgInputs["project-name"])   
            projectcfgAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=projectcfgId)
            if not projectcfgAuthorized:
                raise HTTP_403('Access denied to this project for config')
           
            # read the file
            cfgInputs = TestConfig.DataModel()
            resInputs = cfgInputs.load( absPath = "%s/%s/%s" % (RepoTests.instance().testsPath, projectcfgId, testcfgInputs["testcfg-path"]) )
            if not resInputs: 
                raise HTTP_500('unable to read test config for inputs')
                
        if testcfgOutputs is not None:
            if not isinstance(testcfgOutputs, dict): 
                raise HTTP_400("Bad test config outputs provided in request, dict expected")
            if not ( "project-name" in testcfgOutputs and "testcfg-path" in testcfgOutputs ) :
                raise HTTP_400("Bad test config outputs provided in request, dict expected with project name and path")
           
            if not testcfgOutputs["testcfg-path"].endswith(".tcx"):
                raise HTTP_400('Tcx file required for test config outputs')
                
            # get the project id according to the name and checking authorization
            projectcfgId = ProjectsManager.instance().getProjectID(name=testcfgOutputs["project-name"])   
            projectcfgAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=projectcfgId)
            if not projectcfgAuthorized:
                raise HTTP_403('Access denied to this project for config')
                
            cfgOutputs = TestConfig.DataModel()
            resOutputs = cfgOutputs.load( absPath = "%s/%s/%s" % (RepoTests.instance().testsPath, projectcfgId, testcfgOutputs["testcfg-path"]) )
            if not resOutputs: 
                raise HTTP_500('unable to read test config for outputs')
                
        # read the test file from test repository
        if testExtension == 'tsx':
            doc = TestSuite.DataModel()
            res = doc.load( absPath = "%s/%s/%s" % (RepoTests.instance().testsPath, prjId, testPath) )
            if not res: 
                raise HTTP_500('unable to read test suite')
            
            testData = { 'src-test': doc.testdef, 'src-exec': doc.testexec, 'properties': doc.properties['properties'] }
  
        elif testExtension == 'tux':
            doc = TestUnit.DataModel()
            res = doc.load( absPath = "%s/%s/%s" % (RepoTests.instance().testsPath, prjId, testPath) )
            if not res: 
                raise HTTP_500('unable to read test unit')
                
            testData = { 'testunit': True, 'src-test': doc.testdef, 'src-exec': '', 'properties': doc.properties['properties'] }
                
        elif testExtension == 'tax':
            doc = TestAbstract.DataModel()
            res = doc.load( absPath = "%s/%s/%s" % (RepoTests.instance().testsPath, prjId, testPath) )
            if not res: 
                raise HTTP_500('unable to read test abstract')
            
            testData = { 'testabstract': True, 'src-test': doc.testdef, 'src-exec': '', 'properties': doc.properties['properties'] }
                            
        elif testExtension == 'tpx':
            doc = TestPlan.DataModel()
            res = doc.load( absPath = "%s/%s/%s" % (RepoTests.instance().testsPath, prjId, testPath) )
            if not res: 
                raise HTTP_500('unable to read test plan')

            rslt = RepoTests.instance().addtf2tp( data_= doc.getSorted() )
            if rslt is not None:
                _, err = rslt
                raise HTTP_404('test not found: %s' % err)
            testData = { 'testplan': doc.getSorted(),  'properties': doc.properties['properties'] }
                            
        elif testExtension == 'tgx':
            doc = TestPlan.DataModel()
            res = doc.load( absPath = "%s/%s/%s" % (RepoTests.instance().testsPath, prjId, testPath) )
            if not res: raise HTTP_500('unable to read test plan')

            rslt, alltests = RepoTests.instance().addtf2tg( data_= doc.getSorted() )
            if rslt is not None:
                _, err = rslt
                raise HTTP_404('test not found: %s' % err)
            testData = { 'testglobal': alltests, 'properties': doc.properties['properties'] }
                
        else:
            raise HTTP_403('test extension not accepted: %s' % testExtension )
        
        # personalize test inputs and outputs ?
        if testInputs is not None:
            for newInp in testInputs:
                for origInp in testData["properties"]['inputs-parameters']['parameter']:
                    # if the param exist on the original test than overwrite them
                    if newInp["name"] == origInp["name"]:
                        origInp["value"] = newInp["value"]
                        origInp["type"] = newInp["type"]
        
        if testOutputs is not None:
            for newOut in testOutputs:
                for origOut in testData["properties"]['outputs-parameters']['parameter']:
                    # if the param exist on the original test than overwrite them
                    if newOut["name"] == origOut["name"]:
                        origOut["value"] = newOut["value"]
                        origOut["type"] = newOut["type"]
        
        if testAgents is not None:
            for newAgt in testAgents:
                for origAgt in testData["properties"]["agents"]["agent"]:
                    # if the param exist on the original test than overwrite them
                    if newAgt["name"] == origAgt["name"]:
                        origAgt["value"] = newAgt["value"]
                        origAgt["type"] = newAgt["type"]
              
        if testcfgInputs is not None:
            testData["properties"]['inputs-parameters']['parameter'] = cfgInputs.properties['properties']['parameters']['parameter']
              
        if testcfgOutputs is not None:
            testData["properties"]['outputs-parameters']['parameter'] = cfgOutputs.properties['properties']['parameters']['parameter']
            
        # personalize test description ?
        if sutAdapters is not None:
            for origDescr in testData["properties"]["description"]:
                if origDescr["key"] == "adapters":
                    origDescr["value"] = sutAdapters
                    
        if sutLibraries is not None:
            for origDescr in testData["properties"]["description"]:
                if origDescr["key"] == "libraries":
                    origDescr["value"] = sutLibraries
                    

        # register the test in the task manager
        # extract the extension from test path
        task = TaskManager.instance().registerTask(
                                                    testData=testData, testName=testName, testPath=testPath.rsplit(".", 1)[0], 
                                                    testUser=user_profile['login'], testId=0, testUserId=user_profile['id'],
                                                    testBackground=True, runAt=runAt, runType=runType, runNb=runNb, 
                                                    testProjectId=prjId
                                                  )
        if task.lastError is None:
            # taskID = task.generateTestID()
            taskID = task.getTestID()
            if not taskID: raise HTTP_500('unable to generate test id')
                
        else:
            raise HTTP_500('unable to run test: %s' % task.lastError )
            
        return { "cmd": self.request.path, "message": "test executed", "test-id": taskID }
  
class TestsBasicListing(Handler):
    """
    /rest/tests/basic/listing
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - tests
        summary: Get the listing of all tests in basic mode.
        description: ''
        operationId: testsBasicListing
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id ]
              properties:
                project-id:
                  type: integer
        responses:
          '200':
            description: tests listing
            schema :
              properties:
                cmd:
                  type: string
                tests-listing:
                  type: array
                  items:
                    type: string
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/basic/listing", 
                  "tests-listing": ["/Snippets/UI/03_OpenBrowser.tux", "/Snippets/UI/05_MaximizeBrowser.tux"],
                  "project-id": 1
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        listing = RepoTests.instance().getBasicListing(projectId=prjId)  
        
        return { "cmd": self.request.path, "tests-listing": listing, "project-id": prjId }
  
class TestsListing(Handler):
    """
    /rest/tests/listing
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - tests
        summary: Get the listing of all tests.
        description: ''
        operationId: testsListing
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id ]
              properties:
                project-id:
                  type: integer
                for-saveas:
                  type: boolean
                for-runs:
                  type: boolean
        responses:
          '200':
            description: tests listing
            schema :
              properties:
                cmd:
                  type: string
                tests-listing:
                  type: string
                project-id:
                  type: integer
            examples:
              application/json: |
                {
                  "cmd": "/tests/listing", 
                  "tests-listing": "....",
                  "project-id": 1
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            forsaveas = self.request.data.get("for-saveas")
            forruns = self.request.data.get("for-runs")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        _forsaveas = False
        if forsaveas is not None:
            _forsaveas = forsaveas
            
        _forruns = False
        if forruns is not None:
            _forruns = forruns
             
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        _, _, listing, _ = RepoTests.instance().getTree(b64=True, project=prjId)

        return { "cmd": self.request.path, "tests-listing": listing, "project-id": prjId, 
                 "for-saveas": _forsaveas, "for-runs": _forruns }

class TestsFileUnlockAll(Handler):
    """
    /rest/tests/file/unlock/all
    """   
    @_to_yaml
    def get(self):
        """
        tags:
          - tests
        summary: unlock tests
        description: ''
        operationId: testsFileUnlockAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: tests unlocked
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/file/unlock/all", 
                  "message": "unlocked"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        success = RepoTests.instance().cleanupLocks( )
        if not success:
            raise HTTP_500("Unable to unlock all tests")
            
        return { "cmd": self.request.path, "message": "unlocked" }

class TestsBuild(Handler):
    """
    /rest/tests/build/samples
    """   
    @_to_yaml
    def get(self):
        """
        tags:
          - tests
        summary: build tests samples
        description: ''
        operationId: testsBuildSamples
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: tests packaged
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/build/samples", 
                  "message": "unlocked"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        success = Context.instance().generateSamples()
        if not success:
            raise HTTP_500("Unable to package tests samples")
            
        return { "cmd": self.request.path, "message": "packaged" } 
        
class TestsStatistics(Handler):
    """
    /rest/tests/statistics
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - tests
        summary: get tests statistics files
        description: ''
        operationId: testsStatistics
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                project-name:
                  type: string
                project-id:
                  type: string
        responses:
          '200':
            description: tests statistics
            schema :
              properties:
                cmd:
                  type: string
                statistics:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/statistics", 
                  "statistics": "...."
                }
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")

        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        _, _, _, statistics = RepoTests.instance().getTree(b64=True,  project=prjId )
        
        return { "cmd": self.request.path, "statistics": statistics, "project-id": prjId }
        
class TestsFileDownload(Handler):
    """
    /rest/tests/file/download
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - tests
        summary: download file from the test storage 
        description: ''
        operationId: testsFileDownload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, file-path ]
              properties:
                project-id:
                  type: integer
                file-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                file-content:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/file/download", 
                  "file-content": "...."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a  project id")
            
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success, _, _, _, content, _, _ = RepoTests.instance().getFile(pathFile=filePath, 
                                                                       binaryMode=True, 
                                                                       project=projectId, 
                                                                       addLock=False)  
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to download file")

        return { "cmd": self.request.path, "file-content": content }
        
class TestsFileOpen(Handler):
    """
    /rest/tests/file/open
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - tests
        summary: open and lock file from the test storage 
        description: ''
        operationId: testsFileOpen
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, file-path ]
              properties:
                project-id:
                  type: integer
                file-path:
                  type: string
                ignore-lock:
                  type: boolean
                read-only:
                  type: boolean
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                file-content:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/file/open", 
                  "file-content": "...."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a  project id")
            
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a file path")
            
            _ignoreLock = self.request.data.get("ignore-lock")
            _readOnly = self.request.data.get("read-only")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        ignoreLock = False
        if _ignoreLock is not None:
            ignoreLock = _ignoreLock
        
        readOnly = False
        if _readOnly is not None:
            _readOnly = readOnly
           
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        resultGetFile = RepoTests.instance().getFile(pathFile=filePath, 
                                                    project=projectId, 
                                                    login=user_profile['login'],
                                                    forceOpen=ignoreLock, 
                                                    readOnly=readOnly)  
        success, path_file, name_file, ext_file, project, data_base64, locked, locked_by = resultGetFile
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to open test file")

        return { "cmd": self.request.path, 
                 "file-content": data_base64,
                 "file-path": path_file,
                 "file-name": name_file,
                 "file-extension": ext_file,
                 "locked": locked,
                 "locked-by": locked_by,
                 "project-id": project }

class TestsFileUpload(Handler):
    """
    /rest/tests/file/upload
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - tests
        summary: Upload file the test storage 
        description: ''
        operationId: testsFileUpload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, directory-name, directory-path ]
              properties:
                project-id:
                  type: integer
                directory-name:
                  type: string
                directory-path:
                  type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/directory/rename", 
                  "message": "directory successfully renamed"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a file path")
            fileName = self.request.data.get("file-name")
            if fileName is None: raise EmptyValue("Please specify a file name")
            fileExt = self.request.data.get("file-extension")
            if fileExt is None: raise EmptyValue("Please specify a file extension")
            fileContent = self.request.data.get("file-content")
            if fileContent is None: raise EmptyValue("Please specify a file content")
            
            _overwrite = self.request.data.get("overwrite")
            _closeafter = self.request.data.get("close-after")
            _addfolders = self.request.data.get("add-folders")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        overwrite = False
        if _overwrite is not None:
            overwrite = _overwrite
            
        closeAfter = False
        if _closeafter is not None:
            closeAfter = _closeafter
            
        addFolders = False
        if _addfolders is not None:
            addFolders = _addfolders
            
        putFileReturn = RepoTests.instance().uploadFile( pathFile=filePath, 
                                                         nameFile=fileName, 
                                                         extFile=fileExt, 
                                                         contentFile=fileContent, 
                                                         login=user_profile['login'], 
                                                         project=projectId, 
                                                         overwriteFile=overwrite,
                                                         createFolders=addFolders,
                                                         lockMode=True, 
                                                         binaryMode=True,
                                                         closeAfter=closeAfter )
        success, pathFile, nameFile, extFile, project, overwriteFile, closeAfter, lockedBy = putFileReturn
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to upload file")

        return { "cmd": self.request.path, "message": "file successfully imported",
                 "file-path": pathFile,
                 "file-name": nameFile,
                 "file-extension": extFile,
                 "project-id":  project,
                 "overwrite":  overwriteFile,
                 "close-after": closeAfter,
                 "locked-by": lockedBy }

class TestsFileRemove(Handler):
    """
    /rest/tests/file/remove
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - tests
        summary: remove file in the test storage 
        description: ''
        operationId: testsFileRemove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, file-path  ]
              properties:
                project-id:
                  type: integer
                file-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/file/remove", 
                  "message": "file successfully removed"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            filePath = self.request.data.get("file-path")
            if not filePath: raise EmptyValue("Please specify a file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success = RepoTests.instance().delFile( pathFile=filePath, project=projectId, supportSnapshot=False)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove file")
        if success == Context.instance().CODE_FAILED:
            raise HTTP_403("Remove file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully removed", 
                 "project-id": projectId }
                 
class TestsFileUnlock(Handler):
    """
    /rest/tests/file/unlock
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - tests
        summary: unlock file in the test storage 
        description: ''
        operationId: testsFileUnlock
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, file-path, file-name, file-extension  ]
              properties:
                project-id:
                  type: integer
                file-path:
                  type: string
                file-name:
                  type: string
                file-extension:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/file/unlock", 
                  "message": "file successfully unlocked"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            filePath = self.request.data.get("file-path")
            if filePath is None: raise EmptyValue("Please specify a source filepath")
            fileName = self.request.data.get("file-name")
            if fileName is None: raise EmptyValue("Please specify a source file filename")
            fileExt = self.request.data.get("file-extension")
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')

        success  = RepoTests.instance().unlockFile(pathFile=filePath, 
                                                   nameFile=fileName, 
                                                   extFile=fileExt, 
                                                   project=projectId, 
                                                   login=user_profile["login"])
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to unlock test file")

        return { "cmd": self.request.path, "message": "file sucessfully unlocked", 
                 "project-id": projectId }
                 
class TestsFileRename(Handler):
    """
    /rest/tests/file/rename
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - tests
        summary: Rename file in the test storage 
        description: ''
        operationId: testsFileRename
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, file-name, file-path, file-extension  ]
                  properties:
                    project-id:
                      type: integer
                    file-name:
                      type: string
                    file-path:
                      type: string
                    file-extension:
                      type: string
                destination:
                  type: object
                  required: [ file-name ]
                  properties:
                    file-name:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/file/rename", 
                  "message": "file successfully renamed"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify source")
            projectId = self.request.data.get("source")["project-id"]
            if projectId is None: raise EmptyValue("Please specify a project id")
            filePath = self.request.data.get("source")["file-path"]
            if filePath is None: raise EmptyValue("Please specify a source filepath")
            fileName = self.request.data.get("source")["file-name"]
            if fileName is None: raise EmptyValue("Please specify a source file filename")
            fileExt = self.request.data.get("source")["file-extension"]
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify destination")
            newFileName = self.request.data.get("destination")["file-name"]
            if newFileName is None: raise EmptyValue("Please specify a destination file name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success = RepoTests.instance().renameFile( 
                                                    mainPath=filePath, 
                                                    oldFilename=fileName, 
                                                    newFilename=newFileName, 
                                                    extFilename=fileExt,
                                                    project=projectId, 
                                                    supportSnapshot=False
                                                    )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to rename file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Rename file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully renamed", 
                 "project-id": projectId,
                 "file-path": filePath,
                 "file-name": fileName,
                 "file-extension": fileExt,
                 "new-file-name": newFileName}
        
class TestsFileDuplicate(Handler):
    """
    /rest/tests/file/duplicate
    """   
    @_to_yaml    
    def post(self):
        """
        tags:
          - tests
        summary: Duplicate file in the test storage 
        description: ''
        operationId: testsFileDuplicate
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, file-name, file-path, file-extension  ]
                  properties:
                    project-id:
                      type: integer
                    file-name:
                      type: string
                    file-path:
                      type: string
                    file-extension:
                      type: string
                destination:
                  type: object
                  required: [ project-id, file-path, file-name ]
                  properties:
                    project-id:
                      type: integer
                    file-path:
                      type: string
                    file-name:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/file/rename", 
                  "message": "file successfully renamed"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify source")
            projectId = self.request.data.get("source")["project-id"]
            if projectId is None: raise EmptyValue("Please specify a source projcet-id")
            fileName = self.request.data.get("source")["file-name"]
            if fileName is None: raise EmptyValue("Please specify a source filename")
            filePath = self.request.data.get("source")["file-path"]
            if filePath is None: raise EmptyValue("Please specify a source file path")
            fileExt = self.request.data.get("source")["file-extension"]
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify destination")
            newProjectId = self.request.data.get("destination")["project-id"]
            if newProjectId is None: raise EmptyValue("Please specify a project id")
            newFileName = self.request.data.get("destination")["file-name"]
            if newFileName is None: raise EmptyValue("Please specify a destination file name")
            newFilePath = self.request.data.get("destination")["file-path"]
            if newFilePath is None: raise EmptyValue("Please specify a destination file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
        # checking input    
        if newProjectId is not None:
            if not isinstance(newProjectId, int):
                raise HTTP_400("Bad new project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=newProjectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        newFilePath = os.path.normpath("/" + newFilePath )
        
        success = RepoTests.instance().duplicateFile( 
                                                        mainPath=filePath,
                                                        oldFilename=fileName,
                                                        newFilename=newFileName,
                                                        extFilename=fileExt,
                                                        project=projectId,
                                                        newProject=newProjectId,
                                                        newMainPath=newFilePath
                                                    )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to duplicate file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Duplicate file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file sucessfully duplicated", 
                 "project-id": projectId }
        
class TestsFileMove(Handler):
    """
    /rest/tests/file/move
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - tests
        summary: Move file in the test storage 
        description: ''
        operationId: testsFileMove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, file-name, file-path, file-extension  ]
                  properties:
                    project-id:
                      type: integer
                    file-name:
                      type: string
                    file-path:
                      type: string
                    file-extension:
                      type: string
                destination:
                  type: object
                  required: [ project-id, file-path ]
                  properties:
                    project-id:
                      type: integer
                    file-path:
                      type: string
        responses:
          '200':
            description: move response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/file/move", 
                  "message": "file successfully moved"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify source")
            projectId = self.request.data.get("source")["project-id"]
            if projectId is None: raise EmptyValue("Please specify a project name or a project id")
            filePath = self.request.data.get("source")["file-path"]
            if filePath is None: raise EmptyValue("Please specify a source filename")
            fileName = self.request.data.get("source")["file-name"]
            if fileName is None: raise EmptyValue("Please specify a source file path")
            fileExt = self.request.data.get("source")["file-extension"]
            if fileExt is None: raise EmptyValue("Please specify a source file extension")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify destination")
            newProjectId = self.request.data.get("destination")["project-id"]
            if newProjectId is None: raise EmptyValue("Please specify a new project id")
            newFilePath = self.request.data.get("destination")["file-path"]
            if newFilePath is None: raise EmptyValue("Please specify a destination file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
        # checking input    
        if newProjectId is not None:
            if not isinstance(newProjectId, int):
                raise HTTP_400("Bad new project id provided in request, int expected")

        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=newProjectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        newFilePath = os.path.normpath("/" + newFilePath )
        
        success = RepoTests.instance().moveFile( 
                                                        mainPath=filePath, 
                                                        fileName=fileName, 
                                                        extFilename=fileExt, 
                                                        newPath=newFilePath, 
                                                        project=projectId, 
                                                        newProject=newProjectId,
                                                        supportSnapshot=True
                                                    )
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to move file")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Move file denied")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("File does not exists")
            
        return { "cmd": self.request.path, "message": "file successfully moved", 
                 "project-id": projectId  }

class TestsFileInstance(Handler):
    """
    Find tests in instance in all test plans or test globals
    """   
    def post(self):
        """
        Find tests in instance in all test plans or test globals
        Send POST request (uri /rest/tests/file/instance) with the following body JSON 
        { [ "project-id": <integer>] [, "project-name": <string>] , "file-path": "/" }
        Cookie session_id is mandatory.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
            
            filePath = self.request.data.get("file-path")
            if  not filePath: raise EmptyValue("Please specify a file path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: 
            prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        else:
            projectName = ProjectsManager.instance().getProjectName(prjId=projectId)
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # avoid directory traversal
        filePath = os.path.normpath("/" + filePath )
        
        success, tests = RepoTests.instance().findInstance( filePath=filePath, projectName=projectName, projectId=prjId)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to find tests instance")

        return { "cmd": self.request.path, "tests-instance": tests }
        
class TestsDirectoryAdd(Handler):
    """
    /rest/tests/directory/add
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - tests
        summary: Add directory in the test storage 
        description: ''
        operationId: testsDirectoryAdd
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, directory-name, directory-path ]
              properties:
                project-id:
                  type: integer
                directory-name:
                  type: string
                directory-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/directory/add", 
                  "message": "directory successfully added"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            folderName = self.request.data.get("directory-name")
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            
            folderPath = self.request.data.get("directory-path")
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        
        success = RepoTests.instance().addDir(pathFolder=folderPath, folderName=folderName, project=prjId)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to add directory")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully added", 
                 "project-id": prjId }
        
class TestsDirectoryRename(Handler):
    """
    /rest/tests/directory/rename
    """   
    @_to_yaml   
    def post(self):
        """
        tags:
          - tests
        summary: Rename directory in the test storage 
        description: ''
        operationId: testsDirectoryRename
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, directory-name, directory-path ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
                    directory-path:
                      type: string
                destination:
                  type: object
                  required: [ project-id, directory-name ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/directory/rename", 
                  "message": "directory successfully renamed"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
		
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify source")
            projectId = self.request.data.get("source")["project-id"]
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            folderName = self.request.data.get("source")["directory-name"]
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            folderPath = self.request.data.get("source")["directory-path"]
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify destination")
            newFolderName = self.request.data.get("destination")["directory-name"]
            if newFolderName is None: raise EmptyValue("Please specify a destination folder name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        
        success = RepoTests.instance().renameDir(mainPath=folderPath, oldPath=folderName, 
                                                 newPath=newFolderName, project=projectId)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to rename directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to rename directory: source directory not found")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully renamed", 
                 "project-id": projectId, "directory-name": folderName, 
                 "directory-path": folderPath, "new-directory-name": newFolderName  }
        
class TestsDirectoryDuplicate(Handler):
    """
    /rest/tests/directory/duplicate
    """   
    @_to_yaml  
    def post(self):
        """
        tags:
          - tests
        summary: Duplicate directory in the test storage 
        description: ''
        operationId: testsDirectoryDuplicate
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, directory-name, directory-path ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
                    directory-path:
                      type: string
                destination:
                  type: object
                  required: [ project-id, file-name ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
                    directory-path:
                      type: string
        responses:
          '200':
            description: rename response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/directory/rename", 
                  "message": "directory successfully renamed"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        # get the user profile
        user_profile = _get_user(request=self.request)
        
        # checking json request on post
        projectId = None
        newProjectId = None
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            
            projectId = self.request.data.get("source")["project-id"]
            if projectId is None: raise EmptyValue("Please specify a project id")
            folderName = self.request.data.get("source")["directory-name"]
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            folderPath = self.request.data.get("source")["directory-path"]
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
            
            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            
            newProjectId = self.request.data.get("destination")["project-id"]
            if newProjectId is None: raise EmptyValue("Please specify a project id")
            newFolderName = self.request.data.get("destination")["directory-name"]
            if newFolderName is None: raise EmptyValue("Please specify a destination folder name")
            newFolderPath = self.request.data.get("destination")["directory-path"]
            if newFolderPath is None: raise EmptyValue("Please specify a destination folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
        # checking input    
        if newProjectId is not None:
            if not isinstance(newProjectId, int):
                raise HTTP_400("Bad new project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=newProjectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        # some security check to avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        newFolderPath = os.path.normpath("/" + newFolderPath )
        
        # all ok, do the duplication
        success = RepoTests.instance().duplicateDir(
                                                    mainPath=folderPath, oldPath=folderName, 
                                                    newPath=newFolderName, project=projectId, 
                                                    newProject=newProjectId, 
                                                    newMainPath=newFolderPath
                                                )  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to duplicate directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to duplicate directory: source directory not found")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully duplicated",
                 "project-id": projectId }
        
class TestsDirectoryMove(Handler):
    """
    /rest/tests/directory/move
    """   
    @_to_yaml   
    def post(self):
        """
        tags:
          - tests
        summary: Move directory in the test storage 
        description: ''
        operationId: testsDirectoryMove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ source, destination ]
              properties:
                source:
                  type: object
                  required: [ project-id, directory-name, directory-path  ]
                  properties:
                    project-id:
                      type: integer
                    directory-name:
                      type: string
                    directory-path:
                      type: string
                destination:
                  type: object
                  required: [ project-id, directory-path ]
                  properties:
                    project-id:
                      type: integer
                    directory-path:
                      type: string
        responses:
          '200':
            description: move response
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/directory/move", 
                  "message": "directory successfully moved"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        # get the user profile
        user_profile = _get_user(request=self.request)
        
        # checking json request on post
        projectId = None
        newProjectId = None
        try:
            source = self.request.data.get("source")
            if source is None: raise EmptyValue("Please specify a source")
            projectId = self.request.data.get("source")["project-id"]
            if projectId is None: raise EmptyValue("Please specify a project id")
            folderName = self.request.data.get("source")["directory-name"]
            if folderName is None: raise EmptyValue("Please specify a source folder name")
            folderPath = self.request.data.get("source")["directory-path"]
            if folderPath is None: raise EmptyValue("Please specify a source folder path")

            destination = self.request.data.get("destination")
            if destination is None: raise EmptyValue("Please specify a destination")
            newProjectId = self.request.data.get("destination")["project-id"]
            if newProjectId is None: raise EmptyValue("Please specify a project id")
            newFolderPath = self.request.data.get("destination")["directory-path"]
            if newFolderPath is None: raise EmptyValue("Please specify a destination folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
        # checking input    
        if newProjectId is not None:
            if not isinstance(newProjectId, int):
                raise HTTP_400("Bad new project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        # get the project id according to the name and checking authorization
        newPrjId = newProjectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=newPrjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        # some security check to avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )
        newFolderPath = os.path.normpath("/" + newFolderPath )
        
        # all ok, do the duplication
        success = RepoTests.instance().moveDir(
                                                    mainPath=folderPath, 
                                                    folderName=folderName, 
                                                    newPath=newFolderPath, 
                                                    project=prjId, 
                                                    newProject=newPrjId
                                                )  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to move directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to move directory: source directory not found")
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_403("Directory already exists")
            
        return { "cmd": self.request.path, "message": "directory successfully moved", 
                 "project-id": prjId }
        
class TestsDirectoryRemove(Handler):
    """
    /rest/tests/directory/remove
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - tests
        summary: remove directory in the test storage 
        description: ''
        operationId: testsDirectoryRemove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, directory-path  ]
              properties:
                project-id:
                  type: integer
                directory-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/directory/remove", 
                  "message": "directory successfully removed"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            folderPath = self.request.data.get("directory-path")
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )

        success = RepoTests.instance().delDir(folderPath, projectId)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to remove directory (missing)")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("Cannot remove directory")
                
        return { "cmd": self.request.path, "message": "directory successfully removed",
                 "project-id": projectId }
        
class TestsDirectoryRemoveAll(Handler):
    """
    /rest/tests/directory/remove/all
    """   
    @_to_yaml 
    def post(self):
        """
        tags:
          - tests
        summary: remove all directories in the test storage 
        description: ''
        operationId: testsDirectoryRemoveAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, directory-path  ]
              properties:
                project-id:
                  type: integer
                directory-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/directory/remove/all", 
                  "message": "all directories successfully removed"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            folderPath = self.request.data.get("directory-path")
            if folderPath is None: raise EmptyValue("Please specify a source folder path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')

        # avoid directory traversal
        folderPath = os.path.normpath("/" + folderPath )

        success = RepoTests.instance().delDirAll(folderPath, prjId)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove directory")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to remove directory (missing)")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("Removing directory denied")

        return { "cmd": self.request.path, "message": "all directories successfully removed",
                 "project-id": prjId }

class TestsBackup(Handler):
    """
    /rest/tests/backup
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tests
        summary: Make a backup of all tests
        description: ''
        operationId: testsBackup
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                backup-name:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/backup", 
                  "message": "created"
                }
          '400':
            description: Bad request provided
          '401':
            description: unauthorized
        """
        user_profile = _get_user(request=self.request)

        try:
            backupName = self.request.data.get("backup-name")
            if backupName is None: 
                raise EmptyValue("Please specify a backupName")            
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success =  RepoTests.instance().createBackup(backupName=backupName)  
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to create backup")
            
        return { "cmd": self.request.path, "message": "created" }
        
class TestsBackupDownload(Handler):
    """
    /rest/tests/backup/download
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tests
        summary: Download backup file
        description: ''
        operationId: testsBackupDownload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                backup-name:
                  type: string
                dest-name:
                  type: string
        responses:
          '200':
            description: backup file
            schema :
              properties:
                cmd:
                  type: string
                backup:
                  type: string
                  description: backup file in base64
                dest-name:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/rest/tests/backup/download", 
                  "backup": "....",
                  "dest-name": "..."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        try:
            destName = self.request.data.get("dest-name")
            backupName = self.request.data.get("backup-name")
            if backupName is None: raise EmptyValue("Please specify a backup name")
            if destName is None: raise EmptyValue("Please specify a dest name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        success, _, _, _, backupb64, _ = RepoTests.instance().getBackup(pathFile=backupName, project='')
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to download backup test")
            
        return { "cmd": self.request.path, "backup": backupb64, "dest-name": destName }
        
class TestsBackupRemoveAll(Handler):
    """
    /rest/tests/backup/remove/all
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - tests
        summary: remove all backups from tests
        description: ''
        operationId: testsBackupRemoveAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/tests/backup/remove/all", 
                  "message": "deleted"
                }
          '401':
            description: access denied, unauthorized
          '500':
            description: server error
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        success = RepoTests.instance().deleteBackups()  
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to delete all backups tests")
            
        return { "cmd": self.request.path, "message": "deleted" }

class TestsReset(Handler):
    """
    /rest/tests/reset
    """
    @_to_yaml    
    def get(self):
        """
        tags:
          - tests
        summary: reset tests
        description: ''
        operationId: testsReset
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: tests uninstalled
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/reset", 
                  "message": "reseted"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        success = RepoTests.instance().emptyRepo(projectId='')
        if not success:
            raise HTTP_500("Unable to reset tests")
            
        return { "cmd": self.request.path, "message": "reseted" }

class TestsBackupListing(Handler):
    """
    /rest/tests/backup/listing
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - tests
        summary: return the list of all backups
        description: ''
        operationId: testsBackupListing
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                backups:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/backup/listing", 
                  "backups": "..."
                }
          '400':
            description: Bad request provided
          '401':
            description: unauthorized
        """
        user_profile = _get_user(request=self.request)

        backups =  RepoTests.instance().getBackups()  

        return { "cmd": self.request.path, "backups": backups }

class TestsSnapshotAdd(Handler):
    """
    /rest/tests/snapshot/add
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tests
        summary: add a snapshot
        description: ''
        operationId: testsSnapshotAdd
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, test-path, snapshot-name, snapshot-timestamp ]
              properties:
                project-id:
                  type: integer
                test-path:
                  type: string
                snapshot-name:
                  type: string
                snapshot-timestamp:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/rest/tests/snapshot/add", 
                  "message": "snapshot successfully added"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            testPath = self.request.data.get("test-path")
            if testPath is None: raise EmptyValue("Please specify a test path")
            
            snapshotName = self.request.data.get("snapshot-name")
            if snapshotName is None: raise EmptyValue("Please specify a snapshot name")
            snapshotTimestamp = self.request.data.get("snapshot-timestamp")
            if snapshotTimestamp is None: raise EmptyValue("Please specify a snapshot timestamp")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success = RepoTests.instance().addSnapshot( snapshotName=snapshotName, 
                                                    snapshotTimestamp=snapshotTimestamp,
                                                    testPath=testPath, 
                                                    testPrjId=projectId )
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to find the test provided")
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to add the snapshot")
            
        return { "cmd": self.request.path, "message": "snapshot successfully added",
                 "project-id": projectId}
        
class TestsSnapshotRemove(Handler):
    """
    /rest/tests/snapshot/remove
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tests
        summary: remove a snapshot
        description: ''
        operationId: testsSnapshotRemove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, snapshot-name, snapshot-path ]
              properties:
                project-id:
                  type: integer
                snapshot-name:
                  type: string
                snapshot-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/rest/tests/snapshot/remove", 
                  "message": "snapshot removed"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            snapshotName = self.request.data.get("snapshot-name")
            if snapshotName is None: raise EmptyValue("Please specify a snapshot name")
            snapshotPath = self.request.data.get("snapshot-path")
            if snapshotPath is None: raise EmptyValue("Please specify a snapshot path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success = RepoTests.instance().deleteSnapshot( 
                                                        snapshotPath=snapshotPath,
                                                        snapshotName=snapshotName,
                                                        snapshotPrjId=projectId
                                                        )
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to find the snapshot provided")
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove the snapshot")
            
        return { "cmd": self.request.path, "message": "snapshot removed", "project-id": projectId }
        
class TestsSnapshotRemoveAll(Handler):
    """
    /rest/tests/snapshot/remove/all
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tests
        summary: remove all snapshots according to the test provided
        description: ''
        operationId: testsSnapshotRemoveAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, test-path, test-name, test-extension ]
              properties:
                project-id:
                  type: integer
                test-path:
                  type: string
                test-name:
                  type: string
                test-extension:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/rest/tests/snapshot/remove/all", 
                  "message": "all snapshots removed"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            testPath = self.request.data.get("test-path")
            if testPath is None: raise EmptyValue("Please specify a test path")
            testName = self.request.data.get("test-name")
            if testName is None: raise EmptyValue("Please specify a test name")
            testExt = self.request.data.get("test-extension")
            if testExt is None: raise EmptyValue("Please specify a test extension")
       
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success =  RepoTests.instance().deleteAllSnapshots( testPath=testPath, 
                                                            testPrjId=projectId,
                                                            testName=testName,
                                                            testExt=testExt
                                                            )
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to find the test provided")
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to delete all snapshots")
            
        return { "cmd": self.request.path, "message": "all snapshots deleted", "project-id": projectId }
        
class TestsSnapshotRestore(Handler):
    """
    /rest/tests/snapshot/restore
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - tests
        summary: restore snapshot
        description: ''
        operationId: testsSnapshotRestore
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, snapshot-name, snapshot-path ]
              properties:
                project-id:
                  type: integer
                snapshot-name:
                  type: string
                snapshot-path:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/rest/tests/snapshot/restore", 
                  "message": "snapshot restored"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            snapshotName = self.request.data.get("snapshot-name")
            if snapshotName is None: raise EmptyValue("Please specify a snapshot name")
            snapshotPath = self.request.data.get("snapshot-path")
            if snapshotPath is None: raise EmptyValue("Please specify a snapshot path")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=projectId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success =  RepoTests.instance().restoreSnapshot( 
                                                            snapshotPath=snapshotPath,
                                                            snapshotName=snapshotName,
                                                            snapshotPrjId=projectId
                                                        )
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to find the snapshot provided")
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to restore the snapshot")
            
        return { "cmd": self.request.path, "message": "snapshot restored", "project-id": projectId }
 
"""
Variables handlers
"""
class VariablesAdd(Handler):
    """
    /rest/variables/add/
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - variables
        summary: Add test variable in project, variables can be accessible from test
        description: ''
        operationId: variablesAdd
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ project-id, variable-name,variable-value]
              properties:
                variable-name:
                  type: string
                variable-value:
                  type: string
                  description: in json format
                project-id:
                  type: integer
        responses:
          '200':
            description: variable successfully added
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                variable-id:
                  type: string
            examples:
              application/json: |
                {
                  "message": "variable successfully added",
                  "cmd": "/variables/add",
                  "variable-id": "95"
                }
          '400':
            description: Bad request provided | Bad project id provided | Bad json provided in value
          '403':
            description: Access denied to this project | Variable already exists
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")

            variableName = self.request.data.get("variable-name")
            if not variableName: raise EmptyValue("Please specify the name of the variable")
            
            variableJson = self.request.data.get("variable-value")
            if not variableJson: raise EmptyValue("Please specify the value of the variable")

        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # dumps the json
        try:
            variableValue = json.dumps(variableJson)
        except Exception :
            raise HTTP_400("Bad json provided in value")
         
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success, details = RepoTests.instance().addVariableInDB(projectId=prjId, variableName=variableName,
                                                                variableValue=variableValue)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
        if success == Context.instance().CODE_ALREADY_EXISTS:
            raise HTTP_403(details)
            
        return { "cmd": self.request.path, "message": "variable successfully added", "variable-id": details }
        
class VariablesDuplicate(Handler):
    """
    /rest/variables/duplicate
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - variables
        summary: Duplicate test variable in project
        description: ''
        operationId: variablesDuplicate
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [project-id, variable-id]
              properties:
                variable-id:
                  type: string
                project-id:
                  type: integer
        responses:
          '200':
            description: variable successfully duplicated
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                variable-id:
                  type: string
            examples:
              application/json: |
                {
                  "message": "variable successfully duplicated",
                  "cmd": "/variables/duplicate",
                  "variable-id": "95"
                }
          '400':
            description: Bad request provided | Bad project id provided | Bad json provided in value
          '403':
            description: Access denied to this project
          '404':
            description: Variable not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")

            variableId = self.request.data.get("variable-id")
            if not variableId: raise EmptyValue("Please specify a variable id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
        
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success, details = RepoTests.instance().duplicateVariableInDB(variableId=variableId, projectId=prjId)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404(details)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)

        return { "cmd": self.request.path, "message": "variable successfully duplicated", "variable-id": details }
        
class VariablesUpdate(Handler):
    """
    /rest/variables/update
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - variables
        summary: Update test variable in project
        description: ''
        operationId: variablesUpdate
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [project-id, variable-id]
              properties:
                variable-id:
                  type: string
                variable-name:
                  type: string
                variable-value:
                  type: string
                  description: with json format
                project-id:
                  type: integer
        responses:
          '200':
            description: variable successfully updated
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "variable successfully updated",
                  "cmd": "/variables/update"
                }
          '400':
            description: Bad request provided | Bad project id provided | Bad json provided in value
          '403':
            description: Access denied to this project
          '404':
            description: Variable not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            variableId = self.request.data.get("variable-id")
            if not variableId : raise HTTP_400("Please specify a variable id")

            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")

            variableName = self.request.data.get("variable-name")
            variableJson = self.request.data.get("variable-value")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # checking input
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # dumps the json
        try:
            variableValue = json.dumps(variableJson)
        except Exception :
            raise HTTP_400("Bad json provided in value")
        
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success, details = RepoTests.instance().updateVariableInDB(variableId=variableId, variableName=variableName, 
                                                                    variableValue=variableValue, projectId=prjId)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404(details)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)

        return { "cmd": self.request.path, "message": "variable successfully updated" }
        
class VariablesReset(Handler):
    """
    /rest/variables/reset
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - variables
        summary: Reset all test variables according to the project
        description: ''
        operationId: variablesReset
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [project-id]
              properties:
                project-id:
                  type: integer
        responses:
          '200':
            description: variables successfully reseted
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "variables successfully reseted",
                  "cmd": "/variables/reset"
                }
          '400':
            description: Bad request provided | Bad project id provided | Bad json provided in value
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # checking input
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success, details = RepoTests.instance().delVariablesInDB(projectId=prjId)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)

        return { "cmd": self.request.path, "message": "variables successfully reseted" }
        
class VariablesRemove(Handler):
    """
    /rest/variables/remove
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - variables
        summary: Remove test variable in project
        description: ''
        operationId: variablesRemove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [project-id, variable-id]
              properties:
                variable-id:
                  type: string
                project-id:
                  type: integer
        responses:
          '200':
            description: variable successfully removed
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "message": "variable successfully removed",
                  "cmd": "/variables/remove"
                }
          '400':
            description: Bad request provided | Bad project id provided | Bad json provided in value
          '403':
            description: Access denied to this project
          '404':
            description: Variable not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            variableId = self.request.data.get("variable-id")
            if not variableId : raise HTTP_400("Please specify a variable id")
            
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # checking input
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success, details = RepoTests.instance().delVariableInDB(variableId=variableId, projectId=prjId)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404(details)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "message": "variable successfully removed" }
        
class VariablesListing(Handler):
    """
    /rest/variables/listing
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - variables
        summary: Get a listing of all test variables according to the project id or name
        description: ''
        operationId: variablesListing
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [project-id]
              properties:
                project-id:
                  type: integer
        responses:
          '200':
            description: variables listing
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                variables:
                  type: array
                  description: variables list in json format
                  items:
                    type: object
                    required: [ project-id, id, name, value ]
                    properties:
                      project-id:
                        type: integer
                      id:
                        type: integer
                      name:
                        type: string
                      value:
                        type: string
            examples:
              application/json: |
                {
                  "variables": [ 
                                 { 
                                  "project_id": 1, 
                                  "id": 1, 
                                  "value": false, 
                                  "name": "DEBUG"
                                 } 
                              ],
                  "cmd": "/variables/listing"
                }
          '400':
            description: Bad request provided | Bad project id provided | Bad json provided in value
          '403':
            description: Access denied to this project
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # checking input
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            

        success, details = RepoTests.instance().getVariablesFromDB(projectId=prjId)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
        
        # new in v17 convert as json the result 
        for d in details:
            d['value'] = json.loads( d['value'] )        
        # end of new
        
        return { "cmd": self.request.path, "message": "listing result", "variables": details }

class VariablesSearchByName(Handler):
    """
    /rest/variables/search/by/name
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - variables
        summary: Search a variable according to the name or id
        description: ''
        operationId: variablesSearchByName
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [project-id, variable-name]
              properties:
                project-id:
                  type: integer
                variable-name:
                  type: string
        responses:
          '200':
            description: search result
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                variable:
                  description: variable in json format in only one match
                  type: object
                  required: [ project-id, id, name, value ]
                  properties:
                    project-id:
                      type: integer
                    id:
                      type: integer
                    name:
                      type: string
                    value:
                      type: string
                variables:
                  type: array
                  description: variables list in json format on several occurences
                  items:
                    type: object
                    required: [ project-id, id, name, value ]
                    properties:
                      project-id:
                        type: integer
                      id:
                        type: integer
                      name:
                        type: string
                      value:
                        type: string
            examples:
              application/json: |
                {
                  "variable": {
                                "project_id": 1, 
                                "id": 95, 
                                "value": "1.0", 
                                "name": "VAR_AUTO"
                              },
                  "cmd": "/variables/search/by/name"
                }
          '400':
            description: Bad request provided | Bad project id provided | Bad json provided in value
          '403':
            description: Access denied to this project
          '404':
            description: Variable not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            variableName = self.request.data.get("variable-name")
            if variableName is None: raise EmptyValue("Please specify the name of the variable")
            
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # checking input
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success, details = RepoTests.instance().getVariableFromDB(projectId=prjId, variableName=variableName)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
        if len(details) == 0:
            raise HTTP_404("Variable not found")

        
        if len(details) == 1:
            # new in v17, convert as json the value
            details[0]['value'] = json.loads( details[0]['value'] )
            # end of new
            return { "cmd": self.request.path, "variable": details[0] }
        else:
            # new in v17 convert value as json
            for d in details:
                d['value'] = json.loads( d['value'] )
            # end of new
            
            return { "cmd": self.request.path, "message": "search result", "variables": details }

class VariablesSearchById(Handler):
    """
    /rest/variables/search/by/id
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - variables
        summary: Search a variable according to the name or id
        description: ''
        operationId: variablesSearchById
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [project-id, variable-id]
              properties:
                project-id:
                  type: integer
                variable-id:
                  type: string
        responses:
          '200':
            description: search result
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                variable:
                  description: variable in json format in only one match
                  type: object
                  required: [ project-id, id, name, value ]
                  properties:
                    project-id:
                      type: integer
                    id:
                      type: integer
                    name:
                      type: string
                    value:
                      type: string
                variables:
                  type: array
                  description: variables list in json format on several occurences
                  items:
                    type: object
                    required: [ project-id, id, name, value ]
                    properties:
                      project-id:
                        type: integer
                      id:
                        type: integer
                      name:
                        type: string
                      value:
                        type: string
            examples:
              application/json: |
                {
                  "variable": {
                                "project_id": 1, 
                                "id": 95, 
                                "value": "1.0", 
                                "name": "VAR_AUTO"
                              },
                  "cmd": "/variables/search/by/id"
                }
          '400':
            description: Bad request provided | Bad project id provided | Bad json provided in value
          '403':
            description: Access denied to this project
          '404':
            description: Variable not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            if projectId is None: raise EmptyValue("Please specify a project id")
            
            variableId = self.request.data.get("variable-id")
            if variableId is None: raise EmptyValue("Please specify the id of the variable")
            
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # checking input
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        success, details = RepoTests.instance().getVariableFromDB(projectId=prjId, variableId=variableId)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
        if len(details) == 0:
            raise HTTP_404("Variable not found")

        
        if len(details) == 1:
            # new in v17, convert as json the value
            details[0]['value'] = json.loads( details[0]['value'] )
            # end of new
            return { "cmd": self.request.path, "variable": details[0] }
        else:
            # new in v17 convert value as json
            for d in details:
                d['value'] = json.loads( d['value'] )
            # end of new
            
            return { "cmd": self.request.path, "message": "search result", "variables": details }

"""
Tests Results handlers
"""
                
class ResultsCompressZip(Handler):
    """
    /rest/results/compress/zip
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Compress test result in one zip file
        description: ''
        operationId: resultsCompressZip
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
        responses:
          '200':
            description: all tests results zipped
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/compress/zip", 
                  "message": "....",
                  "project-id": 22
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")

            testId = self.request.data.get("test-id")
            if not testId: raise EmptyValue("Please specify a project id and test id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        # extract the real test path according the test id
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId, 
                                                                  returnProject=False)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result not found')
        
        success = RepoArchives.instance().createZip(trPath=testPath, projectId=prjId)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500('Unable to create zip file')
            
        return { "cmd": self.request.path, 'project-id': prjId, "message": "zip created" }
                 
class ResultsListingFiles(Handler):
    """
    /rest/results/listing/files
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Get the listing of all tests results
        description: ''
        operationId: resultsListingFiles
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ ]
              properties:
                partial-list:
                  type: boolean
                project-name:
                  type: string
                project-id:
                  type: integer
        responses:
          '200':
            description: all test results with details
            schema :
              properties:
                cmd:
                  type: string
                listing:
                  type: list
                  description: listing all test results
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/listing", 
                  "listing": [...],
                  "nb-folders": 2,
                  "nb-files":  2,
                  "statistics": {...}
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")

            _partial = self.request.data.get("partial-list")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        if _partial is None:
            partialListing = True
        else:
            partialListing = _partial
        
        nb_archs, nb_archs_f, archs, stats_archs = RepoArchives.instance().getTree(b64=False, 
                                                                                   fullTree=not partialListing, 
                                                                                   project=prjId)       
        return { "cmd": self.request.path, "listing": archs, "nb-folders": nb_archs, "nb-files": nb_archs_f, 
                 "statistics": stats_archs, 'project-id': prjId }

class ResultsListingIdByDateTime(Handler):
    """
    /rest/results/listing/id/by/datetime
    """
    @_to_yaml    
    def post(self):
        """
        tags:
          - results
        summary: Get the listing id of all tests results. Support date and time filtering.
        description: ''
        operationId: resultsListingIdByDatetime
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ ]
              properties:
                project-name:
                  type: string
                project-id:
                  type: integer
                date:
                  type: string
                  description: filter results by date "YYYY-MM-DD", returns only results greater than the date provided
                time:
                  type: string
                  description: filter results by time "HH:MM:SS", returns only results greater than the time provided
        responses:
          '200':
            description: all tests results with id
            schema :
              properties:
                cmd:
                  type: string
                listing:
                  type: list
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/reports", 
                  "listing":  [...]
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")

            dateFilter = self.request.data.get("date")
            timeFilter = self.request.data.get("time")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        listing = RepoArchives.instance().getBasicListing(projectId=prjId, 
                                                        dateFilter=dateFilter, 
                                                        timeFilter=timeFilter)  
        
        return { "cmd": self.request.path, "listing": listing, 'project-id': prjId }

class ResultsDownloadResult(Handler):
    """
    /rest/results/download/result
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Get result file in test result
        description: ''
        operationId: resultsDownloadResult
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id, file-name ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
                file-name:
                  type: string
                save-as:
                  type: boolean
                  description: parameter only used in windows client
                save-as-name:
                  type: string
                  description: parameter only used in windows client
        responses:
          '200':
            description: image
            schema :
              properties:
                cmd:
                  type: string
                result:
                  type: string
                  description: in base64
                result-name:
                  type: string
                project-id:
                  type: string
                save-as:
                    type: boolean
                save-as-name:
                    type: string
                    description: in base64
            examples:
              application/json: |
                {
                  "cmd": "/results/download/result", 
                  "result": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "result-name": "....",
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced",
                  "save-as": False,
                  "save-as-dest: ""
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result by id not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            fileName = self.request.data.get("file-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
            if not fileName: raise EmptyValue("Please specify a file name")
			
            testId = self.request.data.get("test-id")
            if not testId: raise EmptyValue("Please specify a project id and test id")
            
            _saveAs = self.request.data.get("save-as")
            _saveAsDest = self.request.data.get("save-as-name")
            
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # extract the real test path according the test id
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId, returnProject=False)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result by id not found')

        saveAs = False
        if _saveAs is not None: saveAs = _saveAs
        saveAsDest = ''
        if _saveAsDest is not None: saveAsDest = _saveAsDest
            
        trxPath = "%s/%s" % (testPath, fileName)
        success, _, nameFile, extFile, b64result, _, _ = RepoArchives.instance().getFile( pathFile=trxPath, 
                                                                                          project=projectId, 
                                                                                          addLock=False)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("Result file not found")
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to get file, check log in server side")
            
        return { "cmd": self.request.path, 'test-id': testId, 'project-id': prjId, 
                 'result': b64result, 'result-name': nameFile, "result-extension": extFile,
                 'save-as': saveAs, 'save-as-name': saveAsDest }
                 
class ResultsDownloadResultUncomplete(Handler):
    """
    /rest/results/download/uncomplete
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Get result events event if the test is not yet terminated
        description: ''
        operationId: resultsDownloadUncomplete
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
        responses:
          '200':
            description: image
            schema :
              properties:
                cmd:
                  type: string
                result:
                  type: string
                  description: in base64
                result-name:
                  type: string
                project-id:
                  type: string
                save-as:
                    type: boolean
                save-as-name:
                    type: string
                    description: in base64
            examples:
              application/json: |
                {
                  "cmd": "/results/download/uncomplete", 
                  "result": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "result-name": "....",
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced",
                  "save-as": False,
                  "save-as-dest: ""
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result by id not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")

            testId = self.request.data.get("test-id")
            if not testId: raise EmptyValue("Please specify a project id and test id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # extract the real test path according the test id
        success, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result by id not found')

        success, trName = RepoArchives.instance().createTrTmp(trPath=testPath)
        if success != Context.instance().CODE_OK:
            raise HTTP_500('Unable to get partial test result')
            
        testPath = testPath.split("/", 1)[1]
        trxPath = "%s/%s" % (testPath, trName)
        success, _, nameFile, extFile, b64result, _, _ = RepoArchives.instance().getFile( pathFile=trxPath, 
                                                                                          project=projectId, 
                                                                                          addLock=False)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("Result file not found")
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to get file, check log in server side")
            
        return { "cmd": self.request.path, 'test-id': testId, 'project-id': prjId, 
                 'result': b64result, 'result-name': nameFile, "result-extension": extFile }
                 
class ResultsDownloadImage(Handler):
    """
    /rest/results/download/image
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Get image (png or jpg) from test result
        description: ''
        operationId: resultsDownloadImage
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
                image-name:
                  type: string
        responses:
          '200':
            description: image
            schema :
              properties:
                cmd:
                  type: string
                image:
                  type: string
                  description: in base64
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/download/image", 
                  "image": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            imageName = self.request.data.get("image-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
            if not imageName: raise EmptyValue("Please specify a image name")
			
            testId = self.request.data.get("test-id")
            if not testId: raise EmptyValue("Please specify a project id and test id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        # extract the real test path according the test id
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId, returnProject=False)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('test not found')

        imagePath = "%s/%s" % (testPath, imageName)
        success, _, _, _, b64img, _, _ = RepoArchives.instance().getFile(pathFile=imagePath, 
                                                                         project=projectId, 
                                                                         addLock=False)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("Image not found")
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to get file, check logs in server side")
            
        return { "cmd": self.request.path, 'test-id': testId, 'project-id': prjId, 'image': b64img }

class ResultsRemove(Handler):
    """
    /rest/results/reset
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Remove all the tests results according to the project provided
        description: ''
        operationId: resultsReset
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ ]
              properties:
                project-name:
                  type: string
                project-id:
                  type: integer
        responses:
          '200':
            description: image
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/reset", 
                  "message": "xxxxxxxx"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
                    
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        success = RepoArchives.instance().emptyRepo(projectId=prjId)  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to reset test results")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("Reset results forbidden")
            
        return { "cmd": self.request.path, "message": "results successfully reseted", 'project-id': prjId }
        
class ResultsRemoveById(Handler):
    """
    /rest/results/remove/by/id
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Remove a test result according to the test id provided
        description: ''
        operationId: resultsRemoveById
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: string
        responses:
          '200':
            description: remove result
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                  description: message
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/remove", 
                  "message": "xxxx",
                  "project-id": 25
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
            
            testId = self.request.data.get("test-id")
            if not testId: raise HTTP_400("Please specify a test id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
                    
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('test not found')
            
        success = RepoArchives.instance().delDirAll(pathFolder=testPath, project='')  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove test result")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to remove test result (missing)")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("Cannot remove test result")
            
        return { "cmd": self.request.path, "message": "test result successfully removed", 'project-id': prjId }

class ResultsRemoveByDate(Handler):
    """
    /rest/results/remove/by/date
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Remove all tests results according to the date provided
        description: ''
        operationId: resultsRemoveByDate
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ date ]
              properties:
                date:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: string
        responses:
          '200':
            description: remove result
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
                  description: message
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/remove/by/date", 
                  "message": "xxxxxxx",
                  "project-id": 25
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
            
            byDate = self.request.data.get("date")
            if not byDate: raise HTTP_400("Please specify a date")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
                    
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')

        success = RepoArchives.instance().delDirAll(pathFolder="%s/%s/" % (prjId, byDate), project='')  
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("Unable to remove all tests results")
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_500("Unable to remove all tests results (missing)")
        if success == Context.instance().CODE_FORBIDDEN:
            raise HTTP_403("Cannot remove all tests results")
            
        return { "cmd": self.request.path, "message": "all tests results successfully removed", 'project-id': prjId }

class ResultsFollow(Handler):
    """
    Follow the result of one or severals results
    """    
    def post(self):
        """
        Follow the result of one or severals results
        Send POST request (uri /rest/results/follow) with the following body JSON 
        { "test-ids": ["xxxxx"] [, "project-id": <integer>] [, "project-name": <string>] }
        Cookie session_id is mandatory.
        
        @return: test status
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            testIds = self.request.data.get("test-ids")
            if not testIds: raise HTTP_400("Please specify a project id and a list of test id")
                
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")

        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        results = []
        for testId in testIds:
            result = { "id": testId }
            founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
            if founded == Context.instance().CODE_NOT_FOUND: raise HTTP_404('test not found')

            state = RepoArchives.instance().getTrState(trPath=testPath)
            verdict = RepoArchives.instance().getTrResult(trPath=testPath)
            progress = RepoArchives.instance().getTrProgress(trPath=testPath)
            result["result"] = { "state": state, "verdict": verdict, "progress": progress['percent'] }

            description = RepoArchives.instance().getTrDescription(trPath=testPath)
            result.update(description)
            
            results.append(result)
        return { "cmd": self.request.path, "results": results, 'project-id': prjId}
    
class ResultsStatus(Handler):
    """
    /rest/results/status
    """   
    @_to_yaml    
    def post(self):
        """
        tags:
          - results
        summary: Get the status of the test (not-running, running, complete).
        description: ''
        operationId: resultsStatus
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: string
        responses:
          '200':
            description: result status of a test
            schema :
              properties:
                cmd:
                  type: string
                test-status:
                  type: string
                  description: running/not-running/complete
                test-progress:
                  type: integer
                  description: progress in percent
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/status", 
                  "test-status": "running", 
                  "test-id": "af0b2587-459e-42eb-a4da-e3e6fa227719",
                  "test-progress": 25
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            testId = self.request.data.get("test-id")
            if not testId: raise HTTP_400("Please specify a list of test id")
                
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")

        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result not found')
            
        state = RepoArchives.instance().getTrState(trPath=testPath)
        progress = RepoArchives.instance().getTrProgress(trPath=testPath)
        return { "cmd": self.request.path, 'test-id': testId, 'test-status': state, 'test-progress': progress['percent'] }
    
class ResultsVerdict(Handler):
    """
    /rest/results/verdict
    """
    @_to_yaml      
    def post(self):
        """
        tags:
          - results
        summary: Get the end result of the test (undefined, pass, fail).
        description: ''
        operationId: resultsVerdict
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: string
        responses:
          '200':
            description: tests end result
            schema :
              properties:
                cmd:
                  type: string
                test-verdict:
                  type: string
                  description: undefined, pass, fail
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/verdict", 
                  "test-verdict": "undefined",
                  "test-id": "af0b2587-459e-42eb-a4da-e3e6fa227719"
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
        
        try:
            testId = self.request.data.get("test-id")
            if not testId: raise HTTP_400("Please specify a list of test id")
                
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
            
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result not found')
            
        verdict = RepoArchives.instance().getTrEndResult(trPath=testPath)
        return { "cmd": self.request.path, 'test-id': testId, 'test-verdict': verdict }

class ResultsReportReviews(Handler):
    """
    /rest/results/report/reviews
    """
    @_to_yaml  
    def post(self):
        """
        tags:
          - reports
        summary: Get all report reviews
        description: ''
        operationId: resultsReportReviews
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
                replay-id:
                  type: string
        responses:
          '200':
            description: all test reports
            schema :
              properties:
                cmd:
                  type: string
                test-report:
                  type: string
                  description: in base64 and gzipped
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/reports", 
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced",
                  "basic-review": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "review": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV...."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            testId = self.request.data.get("test-id")
            if not testId: raise HTTP_400("Please specify a test id")
                
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: 
                raise EmptyValue("Please specify a project name or a project id")
                
            _replayId = self.request.data.get("replay-id")    
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        if _replayId is None:
            replayId = 0
        else:
            replayId = _replayId
            
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result not found')
        
        ret = { "cmd": self.request.path, 'test-id': testId }
        
        # reviews
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId,
                                                                         trExt="tbrp")
        if success == Context.instance().CODE_OK:
            ret["basic-review"] = report
        else:
            self.error("Error to get basic report from test result")
            
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId,
                                                                         trExt="trp")
        if success == Context.instance().CODE_OK:
            ret["review"] = report
        else:
            self.error("Error to get report from test result")
            
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId, 
                                                                         trExt="trpx")
        if success == Context.instance().CODE_OK:
            ret["xml-review"] = report
        else:
            self.error("Error to get xml report from test result")

        return ret

class ResultsReportVerdicts(Handler):
    """
    /rest/results/report/verdicts
    """
    @_to_yaml  
    def post(self):
        """
        tags:
          - reports
        summary: Get all report verdicts.
        description: ''
        operationId: resultsReportVerdicts
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
                replay-id:
                  type: string
        responses:
          '200':
            description: all test reports
            schema :
              properties:
                cmd:
                  type: string
                test-report:
                  type: string
                  description: in base64 and gzipped
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/reports", 
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced",
                  "verdict": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "xml-verdict": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV...."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            testId = self.request.data.get("test-id")
            if not testId: raise HTTP_400("Please specify a test id")
                
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: 
                raise EmptyValue("Please specify a project name or a project id")
                
            _replayId = self.request.data.get("replay-id")    
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        if _replayId is None:
            replayId = 0
        else:
            replayId = _replayId
            
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result not found')
        
        ret = { "cmd": self.request.path, 'test-id': testId }
        
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId,
                                                                         trExt="trv")
        if success == Context.instance().CODE_OK:
            ret["verdict"] = report
        else:
            self.error("Error to get csv verdict report from test result")
            
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId,
                                                                         trExt="tvrx")
        if success == Context.instance().CODE_OK:
            ret["xml-verdict"] = report
        else:
            self.error("Error to get csv verdict report from test result")

        return ret

class ResultsReportDesigns(Handler):
    """
    /rest/results/report/designs
    """
    @_to_yaml  
    def post(self):
        """
        tags:
          - reports
        summary: Get all report designs
        description: ''
        operationId: resultsReportDesigns
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
                replay-id:
                  type: string
        responses:
          '200':
            description: all test reports
            schema :
              properties:
                cmd:
                  type: string
                test-report:
                  type: string
                  description: in base64 and gzipped
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/reports", 
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced",
                  "design": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "xml-design": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV...."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            testId = self.request.data.get("test-id")
            if not testId: raise HTTP_400("Please specify a test id")
                
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: 
                raise EmptyValue("Please specify a project name or a project id")
                
            _replayId = self.request.data.get("replay-id")    
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        if _replayId is None:
            replayId = 0
        else:
            replayId = _replayId
            
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result not found')
        
        ret = { "cmd": self.request.path, 'test-id': testId }

        # designs
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId, 
                                                                         trExt="trd")
        if success == Context.instance().CODE_OK:
            ret["design"] = report
        else:
            self.error("Error to get xml report from test result")
            
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId, 
                                                                         trExt="tdsx")
        if success == Context.instance().CODE_OK:
            ret["xml-design"] = report
        else:
            self.error("Error to get xml report from test result")

        return ret

class ResultsReportComments(Handler):
    """
    /rest/results/report/comments
    """
    @_to_yaml  
    def post(self):
        """
        tags:
          - reports
        summary: Get all comments in one report
        description: ''
        operationId: resultsReportComments
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
                replay-id:
                  type: string
        responses:
          '200':
            description: all test reports
            schema :
              properties:
                cmd:
                  type: string
                comments:
                  type: string
                  description: in base64 and gzipped
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/reports", 
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced",
                  "comments": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            testId = self.request.data.get("test-id")
            if not testId: raise HTTP_400("Please specify a test id")
                
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: 
                raise EmptyValue("Please specify a project name or a project id")
                
            _replayId = self.request.data.get("replay-id")    
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        if _replayId is None:
            replayId = 0
        else:
            replayId = _replayId
            
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result not found')
        
        ret = { "cmd": self.request.path, 'test-id': testId }
        
        # comments
        success, report = RepoArchives.instance().getTrComments(trPath=testPath, replayId=replayId)
        if success == Context.instance().CODE_OK:
            ret["comments"] = report
        else:
            self.error("Error to get comments from test result")
         
        return ret

class ResultsReportEvents(Handler):
    """
    /rest/results/report/events
    """
    @_to_yaml  
    def post(self):
        """
        tags:
          - reports
        summary: Get a report of events occured during the test
        description: ''
        operationId: resultsReportEvents
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
                replay-id:
                  type: string
        responses:
          '200':
            description: all test reports
            schema :
              properties:
                cmd:
                  type: string
                events:
                  type: string
                  description: in base64 and gzipped
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/reports", 
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced",
                  "events": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV...."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            testId = self.request.data.get("test-id")
            if not testId: raise HTTP_400("Please specify a test id")
                
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: 
                raise EmptyValue("Please specify a project name or a project id")
                
            _replayId = self.request.data.get("replay-id")    
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        if _replayId is None:
            replayId = 0
        else:
            replayId = _replayId
            
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result not found')
        
        ret = { "cmd": self.request.path, 'test-id': testId }

        # events
        success, report = RepoArchives.instance().getTrResume(trPath=testPath, replayId=replayId)
        if success == Context.instance().CODE_OK:
            ret["events"] = report
        else:
            self.error("Error to get events from test result")
            
        return ret
        
class ResultsReports(Handler):
    """
    /rest/results/reports
    """
    @_to_yaml  
    def post(self):
        """
        tags:
          - reports
        summary: Get all reports of one test (advanced and basic in all formats).
        description: ''
        operationId: resultsReports
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
                replay-id:
                  type: string
        responses:
          '200':
            description: all test reports
            schema :
              properties:
                cmd:
                  type: string
                test-report:
                  type: string
                  description: in base64 and gzipped
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/reports", 
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced",
                  "basic-review": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "review": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "verdict": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "xml-verdict": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "design": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "xml-design": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "comments": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "events": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV...."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            testId = self.request.data.get("test-id")
            if not testId: raise HTTP_400("Please specify a test id")
                
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: 
                raise EmptyValue("Please specify a project name or a project id")
                
            _replayId = self.request.data.get("replay-id")    
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        if _replayId is None:
            replayId = 0
        else:
            replayId = _replayId
            
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result not found')
        
        ret = { "cmd": self.request.path, 'test-id': testId }
        
        # reviews
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId,
                                                                         trExt="tbrp")
        if success == Context.instance().CODE_OK:
            ret["basic-review"] = report
        else:
            self.error("Error to get basic report from test result")
            
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId,
                                                                         trExt="trp")
        if success == Context.instance().CODE_OK:
            ret["review"] = report
        else:
            self.error("Error to get report from test result")
            
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId, 
                                                                         trExt="trpx")
        if success == Context.instance().CODE_OK:
            ret["xml-review"] = report
        else:
            self.error("Error to get xml report from test result")
        
        # verdicts
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId,
                                                                         trExt="trv")
        if success == Context.instance().CODE_OK:
            ret["verdict"] = report
        else:
            self.error("Error to get csv verdict report from test result")
            
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId,
                                                                         trExt="tvrx")
        if success == Context.instance().CODE_OK:
            ret["xml-verdict"] = report
        else:
            self.error("Error to get csv verdict report from test result")

        # designs
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId, 
                                                                         trExt="trd")
        if success == Context.instance().CODE_OK:
            ret["design"] = report
        else:
            self.error("Error to get xml report from test result")
            
        success, report = RepoArchives.instance().getTrReportByExtension(trPath=testPath, replayId=replayId, 
                                                                         trExt="tdsx")
        if success == Context.instance().CODE_OK:
            ret["xml-design"] = report
        else:
            self.error("Error to get xml report from test result")
        
        # comments
        success, report = RepoArchives.instance().getTrComments(trPath=testPath, replayId=replayId)
        if success == Context.instance().CODE_OK:
            ret["comments"] = report
        else:
            self.error("Error to get comments from test result")
         
        # events
        success, report = RepoArchives.instance().getTrResume(trPath=testPath, replayId=replayId)
        if success == Context.instance().CODE_OK:
            ret["events"] = report
        else:
            self.error("Error to get events from test result")
            
        return ret

class ResultsCommentAdd(Handler):
    """
    /rest/results/comment/add
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Add a comment in a test result
        description: ''
        operationId: resultsCommentAdd
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id, comment, timestamp ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
                replay-id:
                  type: string 
                comment:
                  type: string
                timstamp:
                  type: string
        responses:
          '200':
            description: 
            schema :
              properties:
                cmd:
                  type: string
                result:
                  type: string
                  description: in base64
                result-name:
                  type: string
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/download/result", 
                  "result": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "result-name": "....",
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced",
                  "save-as": False,
                  "save-as-dest: ""
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result by id not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            comment = self.request.data.get("comment")
            timestamp = self.request.data.get("timestamp")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
            if not comment: raise EmptyValue("Please specify the comment to add")
            if not timestamp: raise EmptyValue("Please specify a timestamp")

            testId = self.request.data.get("test-id")
            if not testId: raise EmptyValue("Please specify a project id and test id")

            _replayId = self.request.data.get("replay-id")  
            _returnAll = self.request.data.get("return-all")  
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        if _replayId is None:
            replayId = 0
        else:
            replayId = _replayId
        
        if _returnAll is None:
            returnAll = True
        else:
            returnAll = _returnAll
            
        # extract the real test path according the test id
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result by id not found')

        founded, trName = RepoArchives.instance().getTrName(trPath=testPath, replayId=replayId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('trx not found')

        success, _,_, comments = RepoArchives.instance().addComment( archiveUser=user_profile['login'], 
                                                             archivePath="%s/%s" % (testPath,trName), 
                                                             archivePost=comment, 
                                                             archiveTimestamp=timestamp )
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to add comment")
        
        rsp = { "cmd": self.request.path, 'test-id': testId, 'project-id': prjId }
        if returnAll:
            rsp["comments"] = comments
        else:
            rsp["comments"] = []
        return rsp

class ResultsCommentsRemove(Handler):
    """
    /rest/results/comment/remove/all
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Remove all comments in test result
        description: ''
        operationId: resultsCommentsRemoveAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ test-id ]
              properties:
                test-id:
                  type: string
                project-name:
                  type: string
                project-id:
                  type: integer
                replay-id:
                  type: string 
        responses:
          '200':
            description: 
            schema :
              properties:
                cmd:
                  type: string
                result:
                  type: string
                  description: in base64
                result-name:
                  type: string
                project-id:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/download/result", 
                  "result": "eJztfHnPq9iZ5/+R+ju8qqiVbjkV....",
                  "result-name": "....",
                  "test-id": "7dcc4836-e989-49eb-89b7-5ec1351d2ced",
                  "save-as": False,
                  "save-as-dest: ""
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
          '404':
            description: Test result by id not found
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
        
        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")

            testId = self.request.data.get("test-id")
            if not testId: raise EmptyValue("Please specify a project id and test id")

            _replayId = self.request.data.get("replay-id")  

        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], 
                                                                                  projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        if _replayId is None:
            replayId = 0
        else:
            replayId = _replayId

        # extract the real test path according the test id
        founded, testPath = RepoArchives.instance().findTrInCache(projectId=prjId, testId=testId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('Test result by id not found')

        founded, trName = RepoArchives.instance().getTrName(trPath=testPath, replayId=replayId)
        if founded == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404('trx not found')

        success, _ = RepoArchives.instance().delComments( archivePath="%s/%s" % (testPath,trName) )
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to delete all comments")
            
        return  { "cmd": self.request.path, 'test-id': testId, 'project-id': prjId, "message": "all comments deleted" }
"""
Metriscs handlers
"""

class ResultsBackup(Handler):
    """
    /rest/results/backup
    """
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: Make a backup of all tests results
        description: ''
        operationId: resultsBackup
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                backup-name:
                  type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/backup", 
                  "message": "created"
                }
          '400':
            description: Bad request provided
          '401':
            description: unauthorized
        """
        user_profile = _get_user(request=self.request)

        try:
            backupName = self.request.data.get("backup-name")
            if backupName is None: 
                raise EmptyValue("Please specify a backupName")            
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success =  RepoArchives.instance().createBackup(backupName=backupName)  
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to create backup")
            
        return { "cmd": self.request.path, "message": "created" }
        
class ResultsBackupDownload(Handler):
    """
    /rest/results/backup/download
    """
    @_to_yaml    
    def post(self):
        """
        tags:
          - results
        summary: Download backup file
        description: ''
        operationId: resultsBackupDownload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                backup-name:
                  type: string
                dest-name:
                  type: string
        responses:
          '200':
            description: backup file
            schema :
              properties:
                cmd:
                  type: string
                backup:
                  type: string
                  description: backup file in base64
                dest-name:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/rest/results/backup/download", 
                  "backup": "....",
                  "dest-name": "..."
                }
          '400':
            description: Bad request provided
          '403':
            description: Access denied to this project
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        try:
            destName = self.request.data.get("dest-name")
            backupName = self.request.data.get("backup-name")
            if backupName is None: raise EmptyValue("Please specify a backup name")
            if destName is None: raise EmptyValue("Please specify a dest name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success, _, _, _, backupb64, _ = RepoArchives.instance().getBackup(pathFile=backupName, project='')
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to download backup result")
            
        return { "cmd": self.request.path, "backup": backupb64, "dest-name": destName }
        
class ResultsBackupRemoveAll(Handler):
    """
    /rest/results/backup/remove/all
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - results
        summary: remove all backups from test results
        description: ''
        operationId: resultsBackupRemoveAll
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/tests/results/remove/all", 
                  "message": "deleted"
                }
          '401':
            description: access denied, unauthorized
          '500':
            description: server error
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        success = RepoArchives.instance().deleteBackups()  
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to delete all backups results")
            
        return { "cmd": self.request.path, "message": "deleted" } 

class ResultsBackupListing(Handler):
    """
    /rest/results/backup/listing
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - results
        summary: return the list of all backups
        description: ''
        operationId: resultsBackupListing
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            schema :
              properties:
                cmd:
                  type: string
                backups:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/backup/listing", 
                  "backups": "..."
                }
          '400':
            description: Bad request provided
          '401':
            description: unauthorized
        """
        user_profile = _get_user(request=self.request)

        backups =  RepoArchives.instance().getBackups()  

        return { "cmd": self.request.path, "backups": backups }

class ResultsStatistics(Handler):
    """
    /rest/results/statistics
    """   
    @_to_yaml
    def post(self):
        """
        tags:
          - results
        summary: get results statistics files
        description: ''
        operationId: resultsStatistics
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              properties:
                project-name:
                  type: string
                project-id:
                  type: string
        responses:
          '200':
            description: results statistics
            schema :
              properties:
                cmd:
                  type: string
                statistics:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/results/statistics", 
                  "statistics": "...."
                }
        """
        user_profile = _get_user(self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")

        try:
            projectId = self.request.data.get("project-id")
            projectName = self.request.data.get("project-name")
            if not projectId and not projectName: raise EmptyValue("Please specify a project name or a project id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # checking input    
        if projectId is not None:
            if not isinstance(projectId, int):
                raise HTTP_400("Bad project id provided in request, int expected")
                
        # get the project id according to the name and checking authorization
        prjId = projectId
        if projectName: prjId = ProjectsManager.instance().getProjectID(name=projectName)   
        projectAuthorized = ProjectsManager.instance().checkProjectsAuthorization(user=user_profile['login'], projectId=prjId)
        if not projectAuthorized:
            raise HTTP_403('Access denied to this project')
        
        _, _, _, statistics = RepoArchives.instance().getTree(b64=True)
        
        return { "cmd": self.request.path, "statistics": statistics }  

"""
Metrics handlers
"""
class MetricsScriptsStatistics(Handler):
    """
    Get statistics for scripts
    """   
    def post(self):
        """
        Get statistics for scripts
        Send POST request (uri /rest/metrics/scripts/statistics) with the following body JSON 
        { "user-id": <integer>}
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
class MetricsTestsReset(Handler):
    """
    /rest/metrics/tests/reset
    """
    @_to_yaml      
    def get(self):
        """
        tags:
          - metrics
        summary: Reset tests statistics
        description: ''
        operationId: metricsTestsReset
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: statistics reseted
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: message
            examples:
              application/json: |
                {
                  "cmd": "/metrics/reset", 
                  "message": "tests statistics reseted"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)

        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        success = StatsManager.instance().resetStats()
        if not success:
            raise HTTP_500("Unable to reset statistics for tests")
            
        return { "cmd": self.request.path, 'message': 'tests statistics reseted' }

"""
Clients Handler
"""
class ClientsAvailable(Handler):
    """
    /rest/clients/available
    """
    @_to_yaml  
    def post(self):
        """
        tags:
          - clients
        summary: check if a new client is available
        description: ''
        operationId: clientsAvailable
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ client-version, client-platform, client-portable ]
              properties:
                client-version:
                  type: string
                client-platform:
                  type: boolean
                client-portable:
                  type: string
                recheck:
                  type: boolean
        responses:
          '200':
            description: results statistics
            schema :
              properties:
                cmd:
                  type: string
                client-available:
                  type: boolean
                version:
                  type: string
                name:
                  type: string
                recheck:
                  type: boolean
            examples:
              application/json: |
                {
                  "cmd": "/clients/available", 
                  "client-available": True,
                  "version": "1.0.0",
                  "name: "...."
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
   
        try:
            clientVersion = self.request.data.get("client-version")
            clientPlatform = self.request.data.get("client-platform")
            clientPortable = self.request.data.get("client-portable")
            _recheck = self.request.data.get("recheck")
            
            if clientVersion is None: raise HTTP_400("Please specify a client version")
            if clientPlatform is None: raise HTTP_400("Please specify a client platform")
            if clientPortable is None: raise HTTP_400("Please specify a client portable")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        recheck = False
        if _recheck is not None:
            recheck = _recheck
            
        success, newVersion, newPkg = Context.instance().checkClientUpdate( currentVersion= clientVersion, 
                                                                              systemOs = clientPlatform, 
                                                                              portable = clientPortable )
        clientAvailable = False
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500("error to check if a new client is available")
        if success == Context.instance().CODE_OK:
            clientAvailable = True
            
        return { "cmd": self.request.path, "client-available": clientAvailable, 
                 "version": newVersion, "name": newPkg, "recheck": recheck } 

class ClientsDownload(Handler):
    """
    /rest/clients/download
    """
    @_to_yaml  
    def post(self):
        """
        tags:
          - clients
        summary: download client
        description: ''
        operationId: clientsDownload
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ client-platform, client-name ]
              properties:
                client-platform:
                  type: boolean
                client-name:
                  type: string
        responses:
          '200':
            description: results statistics
            schema :
              properties:
                cmd:
                  type: string
                client-binary:
                  type: boolean
            examples:
              application/json: |
                {
                  "cmd": "/clients/download", 
                  "client-binary": "...."
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error 
        """
        user_profile = _get_user(request=self.request)
     
        try:
            clientPlatform = self.request.data.get("client-platform")
            clientName = self.request.data.get("client-name")

            if clientPlatform is None: raise HTTP_400("Please specify a client platform")
            if clientName is None: raise HTTP_400("Please specify a client name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # new in v17, force to download the 64_bit architecture
        if clientPlatform == "win32": clientPlatform = "win64"
        clientPackagePath = '%s%s/%s/%s' % ( Settings.getDirExec(), 
                                             Settings.get( 'Paths', 'clt-package' ),
                                             clientPlatform, 
                                             clientName )
        
        try:
            f = open( clientPackagePath, 'rb')
            data_read = f.read()
            f.close()
        except Exception as e:
            raise HTTP_500("unable to find the client")
            
        return { "cmd": self.request.path, "client-binary": base64.b64encode(data_read), 
                 "client-name": clientName } 

"""
Tools Handler
"""
class ToolsAuthenticate(Handler):
    """
    Disconnect a agent by the name
    """   
    def post(self):
        """
        Disconnect a agent by the name
        Send POST request (uri /rest/agents/disconnect) with the following body JSON 
        { "agent-name"}
        Cookie session_id is mandatory. 
        
        Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        try:
            agentName = self.request.data.get("agent-name")
            if not agentName : raise HTTP_400("Please specify a agent name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        disconnected = AgentsManager.instance().disconnectAgent(name=agentName)
        if disconnected == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("agent not found")
            
        return { "cmd": self.request.path, "message": "agent successfully disconnected" } 
 
"""
Agents handlers
"""
class AgentsRunning(Handler):
    """
    /rest/agents/running
    """
    @_to_yaml   
    def get(self):
        """
        tags:
          - agents
        summary: Get all running agents
        description: ''
        operationId: agentsRunning
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: running agents
            schema :
              properties:
                cmd:
                  type: string
                agents-running:
                  type: array
                  items:
                    type: string
            examples:
              application/json: |
                {
                  "cmd": "/agents/running", 
                  "agents-running": ...
                } 
        """
        user_profile = _get_user(request=self.request)
        
        running = AgentsManager.instance().getRunning()
        return { "cmd": self.request.path, "agents": running }
        
class AgentsDefault(Handler):
    """
    /rest/agents/default
    """
    @_to_yaml   
    def get(self):
        """
        tags:
          - agents
        summary: Get all default agents
        description: ''
        operationId: agentsDefault
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: default agents
            schema :
              properties:
                cmd:
                  type: string
                agents:
                  type: array
                  items:
                    type: string
            examples:
              application/json: |
                {
                  "cmd": "/agents/default", 
                  "agents": ...
                } 
        """
        user_profile = _get_user(request=self.request)
        
        default = AgentsManager.instance().getDefaultAgents(b64=False)
        return { "cmd": self.request.path, "agents": default }
       
class AgentsDisconnect(Handler):
    """
    /rest/agents/disconnect
    """
    @_to_yaml   
    def post(self):
        """
        tags:
          - agents
        summary: Disconnect a agent by the name
        description: ''
        operationId: agentsDisconnect
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ agent-name ]
              properties:
                agent-name:
                  type: string
        responses:
          '200':
            description: 
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/agents/disconnect", 
                  "message: "agent successfully disconnected"
                }
          '400':
            description: Bad request provided
          '404':
            description: Agent not found
        """
        user_profile = _get_user(request=self.request)
  
        try:
            agentName = self.request.data.get("agent-name")
            if not agentName : raise HTTP_400("Please specify a agent name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        disconnected = AgentsManager.instance().disconnectAgent(name=agentName)
        if disconnected == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("agent not found")
            
        return { "cmd": self.request.path, "message": "agent successfully disconnected" }
        
class AgentsConnect(Handler):
    """
    /rest/agents/connect
    """
    @_to_yaml   
    def post(self):
        """
        tags:
          - agents
        summary: connect a agent
        description: ''
        operationId: agentsConnect
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ agent-name, agent-type, agent-description, agent-boot ]
              properties:
                agent-name:
                  type: string
                agent-type:
                  type: string
                agent-description:
                  type: string
                agent-boot:
                  type: boolean
        responses:
          '200':
            description: 
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/agents/connect", 
                  "message: "agent successfully connected"
                }
          '400':
            description: Bad request provided
          '404':
            description: Agent not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
 
        try:
            agentName = self.request.data.get("agent-name")
            agentType = self.request.data.get("agent-type")
            agentDescription = self.request.data.get("agent-description")
            agentBoot = self.request.data.get("agent-boot")
            
            if agentName is None: raise HTTP_400("Please specify a agent name")
            if agentType is None: raise HTTP_400("Please specify a agent type")
            if agentDescription  is None: raise HTTP_400("Please specify a agent description")
            if agentBoot is None: raise HTTP_400("Please specify a agent boot")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        if agentBoot:
            success = AgentsManager.instance().addDefaultAgent( aType = agentType, 
                                                                aName = agentName, 
                                                                aDescr = agentDescription)
            if success != Context.instance().CODE_OK:
                raise HTTP_500("unable to add agent before to connect it")
                
        # start the agent
        success = AgentsManager.instance().startAgent(  atype = agentType, aname = agentName, 
                                                        adescr = agentDescription,
                                                        adefault=False )
        if success != 0:
            raise HTTP_500("unable to start the agent")
            
        return { "cmd": self.request.path, "message": "agent successfully connected" }

class AgentsAdd(Handler):
    """
    /rest/agents/add
    """
    @_to_yaml   
    def post(self):
        """
        tags:
          - agents
        summary: add a agent
        description: ''
        operationId: agentsAdd
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ agent-name, agent-type, agent-description ]
              properties:
                agent-name:
                  type: string
                agent-type:
                  type: string
                agent-description:
                  type: string
        responses:
          '200':
            description: 
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/agents/add", 
                  "message: "agent successfully added"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
            
        try:
            agentName = self.request.data.get("agent-name")
            agentType = self.request.data.get("agent-type")
            agentDescription = self.request.data.get("agent-description")

            if agentName is None: raise HTTP_400("Please specify a agent name")
            if agentType is None: raise HTTP_400("Please specify a agent type")
            if agentDescription  is None: raise HTTP_400("Please specify a agent description")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success = AgentsManager.instance().addDefaultAgent( 
                                                            aType = agentType, 
                                                            aName = agentName,
                                                            aDescr = agentDescription
                                                          )
        if success != Context.instance().CODE_OK:
            raise HTTP_500("unable to add default agent")

        return { "cmd": self.request.path, "message": "agent successfully add" } 

class AgentsRemove(Handler):
    """
    /rest/agents/remove
    """
    @_to_yaml   
    def post(self):
        """
        tags:
          - agents
        summary: remove a agent
        description: ''
        operationId: agentsRemove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ agent-name ]
              properties:
                agent-name:
                  type: string
        responses:
          '200':
            description: 
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/agents/remove", 
                  "message: "agent successfully removed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
   
        try:
            agentName = self.request.data.get("agent-name")
            if not agentName : raise HTTP_400("Please specify a agent name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success = AgentsManager.instance().delDefaultAgent( aName = agentName )
        if success != Context.instance().CODE_OK:
            raise HTTP_500("Unable to remove default agent")
            
        return { "cmd": self.request.path, "message": "agent successfully removed" } 

"""
Probes handlers
"""
class ProbesRunning(Handler):
    """
    /rest/probes/running
    """
    @_to_yaml    
    def get(self):
        """
        tags:
          - probes
        summary: Get all running probes
        description: ''
        operationId: probesRunning
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: running probes
            schema :
              properties:
                cmd:
                  type: string
                probes:
                  type: array
                  items:
                    type: string
            examples:
              application/json: |
                {
                  "cmd": "/probes/running", 
                  "probes": ...
                }
        """
        user_profile = _get_user(request=self.request)
        
        running = ProbesManager.instance().getRunning()
        return { "cmd": self.request.path, "probes": running }
        
class ProbesDefault(Handler):
    """
    /rest/probes/default
    """
    @_to_yaml    
    def get(self):
        """
        tags:
          - probes
        summary: Get all default probes
        description: ''
        operationId: probesDefault
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: default probes
            schema :
              properties:
                cmd:
                  type: string
                probes:
                  type: array
                  items:
                    type: string
            examples:
              application/json: |
                {
                  "cmd": "/probes/default", 
                  "probes": ...
                }
        """
        user_profile = _get_user(request=self.request)
        
        default = ProbesManager.instance().getDefaultProbes(b64=False)
        return { "cmd": self.request.path, "probes": default }
        
class ProbesDisconnect(Handler):
    """
    /rest/probes/disconnect
    """
    @_to_yaml     
    def post(self):
        """
        tags:
          - probes
        summary: Disconnect a probe by the name
        description: ''
        operationId: probesDisconnect
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ probe-name ]
              properties:
                probe-name:
                  type: string
        responses:
          '200':
            description: 
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/probes/disconnect", 
                  "message: "probe successfully disconnected"
                }
          '400':
            description: Bad request provided
          '404':
            description: Probe not found
        """
        user_profile = _get_user(request=self.request)
   
        try:
            probeName = self.request.data.get("probe-name")
            if not probeName : raise HTTP_400("Please specify a probe name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        disconnected = ProbesManager.instance().disconnectProbe(name=probeName)
        if disconnected == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("probe not found")
            
        return { "cmd": self.request.path, "message": "probe successfully disconnected" }
        
class ProbesConnect(Handler):
    """
    /rest/probes/connect
    """
    @_to_yaml   
    def post(self):
        """
        tags:
          - probes
        summary: connect a probe
        description: ''
        operationId: probesConnect
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ probe-name, probe-type, probe-description, probe-boot ]
              properties:
                probe-name:
                  type: string
                probe-type:
                  type: string
                probe-description:
                  type: string
                probe-boot:
                  type: boolean
        responses:
          '200':
            description: 
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/probes/connect", 
                  "message: "probe successfully connected"
                }
          '400':
            description: Bad request provided
          '404':
            description: Probe not found
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
 
        try:
            probeName = self.request.data.get("probe-name")
            probeType = self.request.data.get("probe-type")
            probeDescription = self.request.data.get("probe-description")
            probeBoot = self.request.data.get("probe-boot")
            
            if probeName is None: raise HTTP_400("Please specify a probe name")
            if probeType is None: raise HTTP_400("Please specify a probe type")
            if probeDescription  is None: raise HTTP_400("Please specify a probe description")
            if probeBoot is None: raise HTTP_400("Please specify a probe boot")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        if probeBoot:
            success = ProbesManager.instance().addDefaultProbe( pType = probeType, 
                                                                pName = probeName, 
                                                                pDescr = probeDescription)
            if success != Context.instance().CODE_OK:
                raise HTTP_500("unable to add probe before to connect it")
                
        # start the probe
        success = ProbesManager.instance().startProbe(  ptype = probeType, pname = probeName, 
                                                        pdescr = probeDescription,
                                                        pdefault=False )
        if success != 0:
            raise HTTP_500("unable to start the probe")
            
        return { "cmd": self.request.path, "message": "probe successfully connected" }

class ProbesAdd(Handler):
    """
    /rest/probes/add
    """
    @_to_yaml    
    def post(self):
        """
        tags:
          - probes
        summary: add a probe
        description: ''
        operationId: probesAdd
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ probe-name, probe-type, probe-description ]
              properties:
                probe-name:
                  type: string
                probe-type:
                  type: string
                probe-description:
                  type: string
        responses:
          '200':
            description: 
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/probes/add", 
                  "message: "probe successfully added"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
 
        try:
            probeName = self.request.data.get("probe-name")
            probeType = self.request.data.get("probe-type")
            probeDescription = self.request.data.get("probe-description")

            if probeName is None: raise HTTP_400("Please specify a probe name")
            if probeType is None: raise HTTP_400("Please specify a probe type")
            if probeDescription  is None: raise HTTP_400("Please specify a probe description")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success = ProbesManager.instance().addDefaultProbe( pType = probeType, 
                                                            pName = probeName, 
                                                            pDescr = probeDescription)
        if success != Context.instance().CODE_OK:
            raise HTTP_500("unable to add default probe")
            
        return { "cmd": self.request.path, "message": "probe successfully added" } 
         
class ProbesRemove(Handler):
    """
    /rest/probes/remove
    """
    @_to_yaml    
    def post(self):
        """
        tags:
          - probes
        summary: remove a probe
        description: ''
        operationId: probesRemove
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
          - name: body
            in: body
            required: true
            schema:
              required: [ probe-name ]
              properties:
                probe-name:
                  type: string
        responses:
          '200':
            description: 
            schema :
              properties:
                cmd:
                  type: string
                message:
                  type: string
            examples:
              application/json: |
                {
                  "cmd": "/probes/remove", 
                  "message: "probe successfully removed"
                }
          '400':
            description: Bad request provided
          '500':
            description: Server error
        """
        user_profile = _get_user(request=self.request)
  
        try:
            probeName = self.request.data.get("probe-name")
            if not probeName : raise HTTP_400("Please specify a probe name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success = ProbesManager.instance().delDefaultProbe( pName = probeName )
        if success != Context.instance().CODE_OK:
            raise HTTP_500("unable to remove default probe")
            
        return { "cmd": self.request.path, "message": "probe successfully removed" } 
          
"""
Release notes handlers
"""
class AboutChangesCore(Handler):
    """
    Get the release notes of the product
    """   
    def get(self):
        """
        Get the release notes of the product
        Send GET request (uri /rest/releasenotes/core)
        Cookie session_id is mandatory.

        @return: release notes
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        rn = Context.instance().getRn(pathRn=Settings.getDirExec(), b64=False) 
        return { "cmd": self.request.path, "releasenotes-core": rn }
        
class AboutChangesAdapters(Handler):
    """
    Get the release notes of the adapters
    """   
    def get(self):
        """
        Get the release notes of the adapters
        Send GET request (uri /rest/releasenotes/adapters)
        Cookie session_id is mandatory.

        @return: release notes
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        rn = RepoAdapters.instance().getRn(b64=False)
        return { "cmd": self.request.path, "releasenotes-adapters": rn }
        
class AboutChangesLibraries(Handler):
    """
    Get the release notes of the libraries
    """   
    def get(self):
        """
        Get the release notes of the libraries
        Send GET request (uri /rest/releasenotes/libraries)
        Cookie session_id is mandatory.

        @return: release notes
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        rn = RepoLibraries.instance().getRn(b64=False)
        return { "cmd": self.request.path, "releasenotes-libraries": rn }
        
class AboutChangesToolbox(Handler):
    """
    Get the release notes of the toolbox
    """   
    def get(self):
        """
        Get the release notes of the toolbox
        Send GET request (uri /rest/releasenotes/toolbox)
        Cookie session_id is mandatory.

        @return: release notes
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        rn = ToolboxManager.instance().getRn(b64=False)
        return { "cmd": self.request.path, "releasenotes-toolbox": rn }

"""
System handlers
"""
class SystemVersions(Handler):
    """
    Get information about versions
    """   
    def get(self):
        """
        Get information about versions
        Send GET request (uri /rest/system/versions)
        Cookie session_id is mandatory.

        @return: version of python, php, etc..
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        versions = {}
        versions["core"] = Settings.getVersion()
        versions["python"] = platform.python_version()
        versions["php"] = Context.instance().phpVersion
        versions["database"] = Context.instance().mysqlVersion
        versions["web"] = Context.instance().apacheVersion
        
        return { "cmd": self.request.path, "versions": versions }
        
class SystemNetworking(Handler):
    """
    Get information about the network
    """   
    def get(self):
        """
        Get information about the network
        Send GET request (uri /rest/system/networking)
        Cookie session_id is mandatory.

        @return: version
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        networking = Context.instance().networkInterfaces
        return { "cmd": self.request.path, "networking": networking }
        
class SystemStatus(Handler):
    """
    Get information about the status of the server
    """   
    def get(self):
        """
        Get information about the status of the server
        Send GET request (uri /rest/system/status)
        Cookie session_id is mandatory.

        @return: version
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        status = {}
        status["start-at"] = Context.instance().startedAt
        status["current-date"] = Context.instance().getServerDateTime()
        status["uptime"] = Context.instance().getUptime()
        
        return { "cmd": self.request.path, "status": status }

class SystemUsages(Handler):
    """
    /rest/system/usages
    """
    @_to_yaml
    def get(self):
        """
        tags:
          - system
        summary: get system usages
        description: ''
        operationId: systemUsages
        produces:
          - application/json
        parameters:
          - name: Cookie
            in: header
            description: session_id=NjQyOTVmOWNlMDgyNGQ2MjlkNzAzNDdjNTQ3ODU5MmU5M 
            required: true
            type: string
        responses:
          '200':
            description: usages
            schema :
              properties:
                cmd:
                  type: string
            examples:
              application/json: |
                {
                  "disk": {...},
                  "cmd": "/tasks/running"
                }
          '401':
            description: Access denied
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        usages = {}
        usages["disk"] = Context.instance().getUsage()
        
        return { "cmd": self.request.path, "usages": usages }


"""
Administration handlers
"""
class AdminConfigListing(Handler):
    """
    Get listing of the configuration
    """   
    def get(self):
        """
        Get listing of the configuration
        Send GET request (uri /rest/administration/configuration/listing)
        Cookie session_id is mandatory. only available for administrator

        @return: version
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        config = {}
        for section in Settings.instance().sections():
            for (name,value) in Settings.instance().items(section):
                config["%s-%s" % ( section.lower(), name.lower() )] = value
                
        return { "cmd": self.request.path, "configuration": config }  

class AdminConfigReload(Handler):
    """
    Reload the configuration of the server
    """   
    def get(self):
        """
        Reload the configuration of the server
        Send GET request (uri /rest/administration/configuration/reload)
        Cookie session_id is mandatory. only available for administrator

        @return: version
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        CliFunctions.instance().reload()

        return { "cmd": self.request.path, "status": "reloaded" }  
        
class AdminClientsDeploy(Handler):
    """
    Deploy clients
    """   
    def get(self):
        """
        Deploy clients
        Send GET request (uri /rest/administration/clients/deploy)
        Cookie session_id is mandatory. only available for administrator

        @return: version
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        CliFunctions.instance().deployclients()
        CliFunctions.instance().deployclients(portable=True)
        
        return { "cmd": self.request.path, "status": "deployed" }  

class AdminToolsDeploy(Handler):
    """
    Deploy toolboxes
    """   
    def get(self):
        """
        Deploy toolboxes
        Send GET request (uri /rest/administration/tools/deploy)
        Cookie session_id is mandatory. only available for administrator

        @return: version
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        CliFunctions.instance().deploytools()
        CliFunctions.instance().deploytools(portable=True)
        
        return { "cmd": self.request.path, "status": "deployed" }  

class AdminProjectsListing(Handler):
    """
    Listing projects
    """   
    def get(self):
        """
        List all projects with get request (uri /rest/projects/listing)
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']:
            raise HTTP_401("Access refused")
            
        success, details = ProjectsManager.instance().getProjectsFromDB()
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "projects": details }
        
class AdminProjectsStatistics(Handler):
    """
    Get projects statistics
    """   
    def get(self):
        """
        Get projects statistics with GET request (uri /rest/projects/statistics).
        Cookie session_id is mandatory.
        
        @return: statistics or error
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        success, details = ProjectsManager.instance().getStatisticsFromDb()
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "projects-statistics": details }
        
class AdminProjectsAdd(Handler):
    """
    Add project
    """   
    def post(self):
        """
        Add project
        Send POST request (uri /rest/projects/add) with the following body JSON 
        { "project-name": <string> }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        try:
            projectName = self.request.data.get("project-name")
            if not projectName : raise HTTP_400("Please specify a project name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
        
        success, details = ProjectsManager.instance().addProjectToDB(projectName=projectName)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_400(details)
            
        return { "cmd": self.request.path, "message": "project successfully added", "project-id": details }

class AdminProjectsRename(Handler):
    """
    Rename project
    """   
    def post(self):
        """
        Rename
        Update project 
        Send POST request (uri /rest/projects/rename) with the following body JSON 
        { "project-id": <integer>, "project-name": <string> }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']:
            raise HTTP_401("Access refused")

        try:
            projectId = self.request.data.get("project-id")
            if not projectId : raise HTTP_400("Please specify a project id")
            
            projectName = self.request.data.get("project-name")
            if not projectName : raise HTTP_400("Please specify a project name")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        success, details = ProjectsManager.instance().updateProjectFromDB(projectName=projectName, projectId=projectId)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
        if success == Context.instance().CODE_ALLREADY_EXISTS:
            raise HTTP_400(details)
            
        return { "cmd": self.request.path, "message": "project successfully updated" }

class AdminProjectsRemove(Handler):
    """
    Remove project
    """   
    def post(self):
        """
        Remove project
        Send POST request (uri /rest/projects/remove) with the following body JSON 
        { "project-id": <integer> }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        try:
            projectId = self.request.data.get("project-id")
            if not projectId : raise HTTP_400("Please specify a project id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        success, details = ProjectsManager.instance().delProjectFromDB(projectId=projectId)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)

        return { "cmd": self.request.path, "message": "project successfully removed" } 
        
class AdminProjectsSearch(Handler):
    """
    Search a project according to the name or id
    """   
    def post(self):
        """
        Search a project according to the name or id
        Send POST request (uri /rest/projects/search) with the following body JSON 
        { ["project-name": <string>], ["project-id": <integer>] }
        
        @return: user(s) found
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
        
        try:
            projectName = self.request.data.get("project-name")
            projectId = self.request.data.get("project-id")
            
            if projectName is None and projectId is None: raise EmptyValue("Please specify the name/id of the project")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success, details = ProjectsManager.instance().getProjectFromDB(projectName=projectName, projectId=projectId)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
        if len(details) == 0:
            raise HTTP_500("no project found")
        
        if len(details) == 1:
            return { "cmd": self.request.path, "project": details[0] }
        else:
            return { "cmd": self.request.path, "projects": details }

class AdminUsersProfile(Handler):
    """
    Get user profile
    """   
    def post(self):
        """
        Remove user
        Send POST request (uri /rest/users/profile) with the following body JSON 
        { "user-id": <integer> }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)

        try:
            userId = self.request.data.get("user-id")
            if not userId : raise HTTP_400("Please specify a user id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        if int(userId) != int(user_profile["id"]) and not user_profile['administrator']:
            raise HTTP_401("Access refused")
        else:
            success, details = UsersManager.instance().getUserFromDB(userId=userId)
            if success == Context.instance().CODE_NOT_FOUND:
                raise HTTP_404(details)
            if success == Context.instance().CODE_ERROR:
                raise HTTP_500(details)
                
        return { "cmd": self.request.path, "user": details } 

class AdminUsersListing(Handler):
    """
    Get all users
    """   
    def get(self):
        """
        Get all users with GET request (uri /rest/users/listing).
        Cookie session_id is mandatory.
        
        @return: list of users or error
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']:
            raise HTTP_401("Access refused")
            
        success, details = UsersManager.instance().getUsersFromDB()
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "users": details }
        
class AdminUsersStatistics(Handler):
    """
    Get users statistics
    """   
    def get(self):
        """
        Get users statistics with GET request (uri /rest/users/statistics).
        Cookie session_id is mandatory.
        
        @return: statistics or error
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        success, details = UsersManager.instance().getStatisticsFromDb()
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "users-statistics": details }
        
class AdminUsersAdd(Handler):
    """
    Add project
    """   
    def post(self):
        """
        Add users
        Send POST request (uri /rest/users/add) with the following body JSON 
        { "login": <string>, "password": <sha1>, "email": <string> }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message with user id
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        try:
            login = self.request.data.get("login")
            if not login: raise EmptyValue("Please specify a login")
            
            password = self.request.data.get("password")
            if not password: raise EmptyValue("Please specify a password")
            
            email = self.request.data.get("email")
            if not email: raise EmptyValue("Please specify a email")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
        
        success, details = UsersManager.instance().addUserToDB(login=login, password=password, email=email)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
        if success == Context.instance().CODE_ALREADY_EXISTS:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "message": "user successfully added", "user-id": details }

class AdminUsersUpdate(Handler):
    """
    Update user
    """   
    def post(self):
        """
        Update user 
        Send POST request (uri /rest/users/update) with the following body JSON 
        { "user-id": <integer>, ["email": <string>] }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']:
            raise HTTP_401("Access refused")

        try:
            userId = self.request.data.get("user-id")
            if not userId : raise HTTP_400("Please specify a user id")

            email = self.request.data.get("email")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        success, details = UsersManager.instance().updateUserInDB(userId=userId, email=email)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404(details)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "message": "user successfully updated" }

class AdminUsersRemove(Handler):
    """
    Remove user
    """   
    def post(self):
        """
        Remove user
        Send POST request (uri /rest/users/remove) with the following body JSON 
        { "user-id": <integer> }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        try:
            userId = self.request.data.get("user-id")
            if not userId : raise HTTP_400("Please specify a user id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        # him self deletion deny
        if int(userId) == int(user_profile["id"]):
            raise HTTP_403("deletion not authorized")
            
        success, details = UsersManager.instance().delUserInDB(userId=userId)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404(details)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "message": "user successfully removed" } 

class AdminUsersStatus(Handler):
    """
    Enable or disable a user account
    """   
    def post(self):
        """
        Enable or disable a user account
        Send POST request (uri /rest/users/status) with the following body JSON 
        { "user-id": <integer>, "enabled": True }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        try:
            userId = self.request.data.get("user-id")
            if not userId : raise HTTP_400("Please specify a user id")
            
            enabled = self.request.data.get("enabled")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        # update 
        success, details = UsersManager.instance().updateStatusUserInDB(userId=userId, status=enabled)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404(details)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
        
        if enabled:
            return { "cmd": self.request.path, "message": "user successfully enabled" }
        else:
            return { "cmd": self.request.path, "message": "user successfully disabled" } 
        
class AdminUsersDisconnect(Handler):
    """
    Disconnect a user
    """   
    def post(self):
        """
        Disconnect a user 
        Send POST request (uri /rest/users/disconnect) with the following body JSON 
        { "login": <string> }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        try:
            userLogin = self.request.data.get("login")
            if not userLogin : raise HTTP_400("Please specify a login")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        disconnected = Context.instance().unregisterUserFromXmlrpc(login=userLogin)
        if disconnected == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404("user not found")
            
        return { "cmd": self.request.path, "message": "user successfully disconnected" } 
  
class AdminUsersDuplicate(Handler):
    """
    Duplicate user
    """   
    def post(self):
        """
        Duplicate user
        Send POST request (uri /rest/users/duplicate) with the following body JSON 
        { "user-id": <integer> }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        try:
            userId = self.request.data.get("user-id")
            if not userId : raise HTTP_400("Please specify a user id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        success, details = UsersManager.instance().duplicateUserInDB(userId=userId)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404(details)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "message": "user successfully duplicated", "user-id": details  } 

class AdminUsersPasswordReset(Handler):
    """
    Reset the password of a user 
    """   
    def post(self):
        """
        Reset the password of a user 
        Send POST request (uri /rest/users/password/reset) with the following body JSON 
        { "user-id": <integer> }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        try:
            userId = self.request.data.get("user-id")
            if not userId : raise HTTP_400("Please specify a user id")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
            
        success, details = UsersManager.instance().resetPwdUserInDB(userId=userId)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404(details)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "message": "password successfully reseted" } 
        
class AdminUsersPasswordUpdate(Handler):
    """
    Update the password of a user 
    """   
    def post(self):
        """
        Update the password of a user 
        Send POST request (uri /rest/users/password/update) with the following body JSON 
        { "user-id": <integer>, "current-password": <sha1>, "new-password": <sha1> }
        Cookie session_id is mandatory. Available only for administrator.

        @return: success message
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
            
        try:
            userId = self.request.data.get("user-id")
            if not userId : raise HTTP_400("Please specify a user id")
            
            currentPwd = self.request.data.get("current-password")
            if not currentPwd : raise HTTP_400("Please specify the current password")
            
            newPwd = self.request.data.get("new-password")
            if not newPwd : raise HTTP_400("Please specify the new password")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)
        
        # check current password
        sha1 = sha1_constructor()
        sha1.update( "%s%s" % ( Settings.get( 'Misc', 'salt'), currentPwd )  )
        if sha1.hexdigest() != user_profile['password']:
            raise HTTP_403("bad current password provided")
        
        # update 
        success, details = UsersManager.instance().updatePwdUserInDB(userId=userId, newPwd=newPwd)
        if success == Context.instance().CODE_NOT_FOUND:
            raise HTTP_404(details)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
            
        return { "cmd": self.request.path, "message": "password successfully updated" } 

class AdminUsersSearch(Handler):
    """
    Search a user according to the name or id
    """   
    def post(self):
        """
        Search a user according to the name or id
        Send POST request (uri /rest/users/search) with the following body JSON 
        { ["user-login": <string>], ["user-id": <integer>] }
        
        @return: user(s) found
        @rtype: dict 
        """
        user_profile = _get_user(request=self.request)
        
        if not user_profile['administrator']: raise HTTP_401("Access refused")
           
        try:
            userLogin = self.request.data.get("user-login")
            userId = self.request.data.get("user-id")
            
            if userLogin is None and userId is None: raise EmptyValue("Please specify the name/id of the user")
        except EmptyValue as e:
            raise HTTP_400("%s" % e)
        except Exception as e:
            raise HTTP_400("Bad request provided (%s ?)" % e)

        success, details = UsersManager.instance().getUserFromDB(userId=userId, userLogin=userLogin)
        if success == Context.instance().CODE_ERROR:
            raise HTTP_500(details)
        if len(details) == 0:
            raise HTTP_500("no user found")
        
        if len(details) == 1:
            return { "cmd": self.request.path, "user": details[0] }
        else:
            return { "cmd": self.request.path, "users": details }

"""
Logger
"""
class _NoLoggingWSGIRequestHandler(WSGIRequestHandler, Logger.ClassLogger):
    """
    """
    def log_message(self, format, *args):
        """
        """
        self.trace( "RSI - %s %s %s" % args )

_my_logger = logging.Logger(__name__)
_my_logger.setLevel(logging.DEBUG)
_hnd = logging.StreamHandler(sys.stdout)
_my_logger.addHandler(_hnd)

"""
Webservices routing
"""
class _WebServices(WSGI):
    logger = _my_logger
    debug = False
    routes = [
        # session
        ('/session/login',                              SessionLogin()),
        ('/session/logout',                             SessionLogout()),
        ('/session/refresh',                            SessionRefresh()),
        ('/session/context',                            SessionContext()),
        ('/session/context/all',                        SessionContextAll()),
        
        # agents
        ('/agents/running',                             AgentsRunning()),
        ('/agents/default',                             AgentsDefault()),
        ('/agents/disconnect',                          AgentsDisconnect()),
        ('/agents/connect',                             AgentsConnect()),
        ('/agents/add',                                 AgentsAdd()),
        ('/agents/remove',                              AgentsRemove()),
        
        # probes
        ('/probes/running',                             ProbesRunning()),
        ('/probes/default',                             ProbesDefault()),
        ('/probes/disconnect',                          ProbesDisconnect()),
        ('/probes/connect',                             ProbesConnect()),
        ('/probes/add',                                 ProbesAdd()),
        ('/probes/remove',                              ProbesRemove()),
        
        # tasks
        ('/tasks/running',                              TasksRunning()),
        ('/tasks/waiting',                              TasksWaiting()),
        ('/tasks/history',                              TasksHistory()),
        ('/tasks/history/all',                          TasksHistoryAll()),
        ('/tasks/cancel',                               TasksCancel()),
        ('/tasks/cancel/selective',                     TasksCancelSelective()),
        ('/tasks/cancel/all',                           TasksCancelAll()),
        ('/tasks/history/clear',                        TasksHistoryClear()),
        ('/tasks/replay',                               TasksReplay()),
        ('/tasks/verdict',                              TasksVerdict()),
        ('/tasks/review',                               TasksReview()),
        ('/tasks/design',                               TasksDesign()),
        ('/tasks/comment',                              TasksComment()),
        ('/tasks/kill',                                 TasksKill()),
        ('/tasks/kill/all',                             TasksKillAll()),
        ('/tasks/kill/selective',                       TasksKillSelective()),
        ('/tasks/reschedule',                           TasksReschedule()),
        
        # public storage
        ('/public/basic/listing',                       PublicListing()),
        ('/public/directory/add',                       PublicDirectoryAdd()),
        ('/public/directory/remove',                    PublicDirectoryRemove()),
        ('/public/directory/rename',                    PublicDirectoryRename()),
        ('/public/file/download',                       PublicDownload()),
        ('/public/file/import',                         PublicImport()),
        ('/public/file/remove',                         PublicRemove()),
        ('/public/file/rename',                         PublicRename()),
        
        # tests
        ('/tests/run',                                  TestsRun()),
        ('/tests/basic/listing',                        TestsBasicListing()),
        ('/tests/listing',                              TestsListing()),
        ('/tests/statistics',                           TestsStatistics()),
        ('/tests/directory/add',                        TestsDirectoryAdd()),
        ('/tests/directory/remove',                     TestsDirectoryRemove()),
        ('/tests/directory/remove/all',                 TestsDirectoryRemoveAll()),
        ('/tests/directory/rename',                     TestsDirectoryRename()),
        ('/tests/directory/duplicate',                  TestsDirectoryDuplicate()),
        ('/tests/directory/move',                       TestsDirectoryMove()),
        ('/tests/file/download',                        TestsFileDownload()),
        ('/tests/file/open',                            TestsFileOpen()),
        ('/tests/file/upload',                          TestsFileUpload()),
        ('/tests/file/remove',                          TestsFileRemove()),
        ('/tests/file/rename',                          TestsFileRename()),
        ('/tests/file/duplicate',                       TestsFileDuplicate()),
        ('/tests/file/move',                            TestsFileMove()),
        ('/tests/file/instance',                        TestsFileInstance()),
        ('/tests/file/unlock/all',                      TestsFileUnlockAll()),
        ('/tests/file/unlock',                          TestsFileUnlock()),
        ('/tests/build/samples',                        TestsBuild()),
        ('/tests/backup',                               TestsBackup()),
        ('/tests/backup/listing',                       TestsBackupListing()),
        ('/tests/backup/download',                      TestsBackupDownload()),
        ('/tests/backup/remove/all',                    TestsBackupRemoveAll()),
        ('/tests/reset',                                TestsReset()),
        ('/tests/snapshot/add',                         TestsSnapshotAdd()),
        ('/tests/snapshot/restore',                     TestsSnapshotRestore()),
        ('/tests/snapshot/remove',                      TestsSnapshotRemove()),
        ('/tests/snapshot/remove/all',                  TestsSnapshotRemoveAll()),
        
        # variables
        ('/variables/listing',                          VariablesListing()),
        ('/variables/add',                              VariablesAdd()),
        ('/variables/update',                           VariablesUpdate()),
        ('/variables/remove',                           VariablesRemove()),
        ('/variables/duplicate',                        VariablesDuplicate()),
        ('/variables/reset',                            VariablesReset()),
        ('/variables/search/by/name',                   VariablesSearchByName()),
        ('/variables/search/by/id',                     VariablesSearchById()),

        # tests results storage
        ('/results/listing/files',                      ResultsListingFiles()),
        ('/results/listing/id/by/datetime',             ResultsListingIdByDateTime()),
        ('/results/remove',                             ResultsRemove()),
        ('/results/remove/by/id',                       ResultsRemoveById()),
        ('/results/remove/by/date',                     ResultsRemoveByDate()),
        ('/results/follow',                             ResultsFollow()),
        ('/results/status',                             ResultsStatus()),
        ('/results/verdict',                            ResultsVerdict()),
        ('/results/report/verdicts',                    ResultsReportVerdicts()),
        ('/results/report/reviews',                     ResultsReportReviews()),
        ('/results/report/designs',                     ResultsReportDesigns()),
        ('/results/report/comments',                    ResultsReportComments()),
        ('/results/report/events',                      ResultsReportEvents()),
        ('/results/reports',                            ResultsReports()),
        ('/results/compress/zip',                       ResultsCompressZip()),
        ('/results/download/image',                     ResultsDownloadImage()),
        ('/results/download/result',                    ResultsDownloadResult()),
        ('/results/download/uncomplete',                ResultsDownloadResultUncomplete()),
        ('/results/comment/add',                        ResultsCommentAdd()),
        ('/results/comments/remove',                    ResultsCommentsRemove()),
        ('/results/backup',                             ResultsBackup()),
        ('/results/backup/listing',                     ResultsBackupListing()),
        ('/results/backup/download',                    ResultsBackupDownload()),
        ('/results/backup/remove/all',                  ResultsBackupRemoveAll()),
        ('/results/statistics',                         ResultsStatistics()),
        
        # metrics for test 
        ('/metrics/tests/reset',                        MetricsTestsReset()),
        
        # adapters
        ( '/adapters/add',                              AdaptersAdd()),
        ( '/adapters/statistics',                       AdaptersStatistics()),
        ( '/adapters/syntax/all',                       AdaptersCheckSyntaxAll()),
        ( '/adapters/set/default',                      AdaptersSetDefault()),
        ( '/adapters/set/generic',                      AdaptersSetGeneric()),
        ( '/adapters/build',                            AdaptersBuild()),
        ( '/adapters/backup',                           AdaptersBackup()),
        ( '/adapters/backup/listing',                   AdaptersBackupListing()),
        ( '/adapters/backup/download',                  AdaptersBackupDownload()),
        ( '/adapters/backup/remove/all',                AdaptersBackupRemoveAll()),
        ( '/adapters/reset',                            AdaptersReset()),
        ( '/adapters/listing',                          AdaptersListing()),
        ( '/adapters/file/move',                        AdaptersFileMove()),
        ( '/adapters/file/unlock/all',                  AdaptersFileUnlockAll()),
        ( '/adapters/file/unlock',                      AdaptersFileUnlock()),
        ( '/adapters/file/rename',                      AdaptersFileRename()),
        ( '/adapters/file/duplicate',                   AdaptersFileDuplicate()),
        ( '/adapters/file/remove',                      AdaptersFileRemove()),
        ( '/adapters/file/upload',                      AdaptersFileUpload()),
        ( '/adapters/file/download',                    AdaptersFileDownload()),
        ( '/adapters/file/open',                        AdaptersFileOpen()),
        ( '/adapters/directory/move',                   AdaptersDirectoryMove()),
        ( '/adapters/directory/rename',                 AdaptersDirectoryRename()),
        ( '/adapters/directory/duplicate',              AdaptersDirectoryDuplicate()),
        ( '/adapters/directory/remove',                 AdaptersDirectoryRemove()),
        ( '/adapters/directory/remove/all',             AdaptersDirectoryRemoveAll()),
        ( '/adapters/directory/add',                    AdaptersDirectoryAdd()),
        
        # libraries
        ( '/libraries/add',                             LibrariesAdd()),
        ( '/libraries/statistics',                      LibrariesStatistics()),
        ( '/libraries/syntax/all',                      LibrariesCheckSyntaxAll()),
        ( '/libraries/set/default',                     LibrariesSetDefault()),
        ( '/libraries/set/generic',                     LibrariesSetGeneric()),
        ( '/libraries/build',                           LibrariesBuild()),
        ( '/libraries/backup',                          LibrariesBackup()),
        ( '/libraries/backup/listing',                  LibrariesBackupListing()),
        ( '/libraries/backup/download',                 LibrariesBackupDownload()),
        ( '/libraries/backup/remove/all',               LibrariesBackupRemoveAll()),
        ( '/libraries/reset',                           LibrariesReset()),
        ( '/libraries/listing',                         LibrariesListing()),
        ( '/libraries/file/move',                       LibrariesFileMove()),
        ( '/libraries/file/unlock/all',                 LibrariesFileUnlockAll()),
        ( '/libraries/file/unlock',                     LibrariesFileUnlock()),
        ( '/libraries/file/rename',                     LibrariesFileRename()),
        ( '/libraries/file/duplicate',                  LibrariesFileDuplicate()),
        ( '/libraries/file/remove',                     LibrariesFileRemove()),
        ( '/libraries/file/upload',                     LibrariesFileUpload()),
        ( '/libraries/file/download',                   LibrariesFileDownload()),
        ( '/libraries/file/open',                       LibrariesFileOpen()),
        ( '/libraries/directory/move',                  LibrariesDirectoryMove()),
        ( '/libraries/directory/rename',                LibrariesDirectoryRename()),
        ( '/libraries/directory/duplicate',             LibrariesDirectoryDuplicate()),
        ( '/libraries/directory/remove',                LibrariesDirectoryRemove()),
        ( '/libraries/directory/remove/all',            LibrariesDirectoryRemoveAll()),
        ( '/libraries/directory/add',                   LibrariesDirectoryAdd()),
        
        # documentation
        ( '/documentations/cache',                      DocumentationsCache()),
        ( '/documentations/build',                      DocumentationsBuild()),
        
        # system
        ( '/system/versions',                           SystemVersions()),
        ( '/system/networking',                         SystemNetworking()),
        ( '/system/status',                             SystemStatus()),
        ( '/system/usages',                             SystemUsages()),

        # administration
        ( '/administration/configuration/listing',      AdminConfigListing()),
        ( '/administration/configuration/reload',       AdminConfigReload()),
        ( '/administration/clients/deploy',             AdminClientsDeploy()),
        ( '/administration/tools/deploy',               AdminToolsDeploy()),
        ( '/administration/users/profile',              AdminUsersProfile()),
        ( '/administration/users/listing',              AdminUsersListing()),
        ( '/administration/users/add',                  AdminUsersAdd()),
        ( '/administration/users/remove',               AdminUsersRemove()),
        ( '/administration/users/disconnect',           AdminUsersDisconnect()),
        ( '/administration/users/update',               AdminUsersUpdate()),
        ( '/administration/users/status',               AdminUsersStatus()),
        ( '/administration/users/duplicate',            AdminUsersDuplicate()),
        ( '/administration/users/password/reset',       AdminUsersPasswordReset()),
        ( '/administration/users/password/update',      AdminUsersPasswordUpdate()),
        ( '/administration/users/search',               AdminUsersSearch()),
        ( '/administration/users/statistics',           AdminUsersStatistics()),
        ( '/administration/projects/listing',           AdminProjectsListing()),
        ( '/administration/projects/add',               AdminProjectsAdd()),
        ( '/administration/projects/remove',            AdminProjectsRemove()),
        ( '/administration/projects/rename',            AdminProjectsRename()),
        ( '/administration/projects/search',            AdminProjectsSearch()),
        ( '/administration/projects/statistics',        AdminProjectsStatistics()),
        
        # client
        ( '/clients/available',                         ClientsAvailable()),
        ( '/clients/download',                          ClientsDownload()),

        # toolbox
        ('/tools/authenticate',                         ToolsAuthenticate()),
        
        # plugins
        # /plugins/available
        
        # about
        ('/about/changes/core',                         AboutChangesCore()),
        ('/about/changes/adapters',                     AboutChangesAdapters()),
        ('/about/changes/libraries',                    AboutChangesLibraries()),
        ('/about/changes/toolbox',                      AboutChangesToolbox()),
    ]

class _RestServerInterface(Logger.ClassLogger, threading.Thread):
    def __init__(self, listeningAddress):
        """
        Constructor 

        @param listeningAddress:
        @type listeningAddress: tuple
        """
        threading.Thread.__init__(self)
        self._stopEvent = threading.Event()

        self.httpd = make_server( host=listeningAddress[0], port=listeningAddress[1], 
                                    app=_WebServices, handler_class=_NoLoggingWSGIRequestHandler )

    def run(self):
        """
        Run xml rpc server
        """
        self.trace("REST server started")
        try:
            while not self._stopEvent.isSet():
                self.httpd.handle_request()
        except Exception as e:
            self.error("Exception in REST server thread: " + str(e))
        self.trace("REST server stopped")

    def stop(self):
        """
        Stop the xml rpc server
        """
        self._stopEvent.set()
        self.join()
        
_RSI = None # singleton
def instance ():
    """
    Returns the singleton of the rest server

    @return:
    @rtype:
    """
    return _RSI

def initialize (listeningAddress):
    """
    Rest server instance creation

    @param listeningAddress: listing on ip and port
    @type listeningAddress: tuple
    """
    global _RSI
    _RSI = _RestServerInterface( listeningAddress = listeningAddress)

def finalize ():
    """
    Destruction of the singleton
    """
    global _RSI
    if _RSI:
        _RSI = None
