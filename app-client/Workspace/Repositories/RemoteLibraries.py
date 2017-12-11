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

"""
Remote repository for libraries module
"""

import sys

# unicode = str with python3
if sys.version_info > (3,):
    unicode = str
    
try:
    from PyQt4.QtGui import (QInputDialog, QIcon, QTreeWidgetItem, QLineEdit)
except ImportError:
    from PyQt5.QtGui import (QIcon)
    from PyQt5.QtWidgets import (QInputDialog, QTreeWidgetItem, QLineEdit)

from Libs import QtHelper, Logger

try:
    import RemoteRepository
except ImportError: # support python3
    from . import RemoteRepository
import UserClientInterface as UCI
import RestClientInterface as RCI


class Repository(RemoteRepository.Repository):
    """
    Repository
    """
    def __init__(self, parent):
        """
        Remote repository generic constructor
        """
        RemoteRepository.Repository.__init__(self, parent, repoType=UCI.REPO_LIBRARIES)

    def addLibraries(self):
        """
        Add libraries
        """
        txt, ok = QInputDialog.getText(self, "Main libraries name", "Enter name:", QLineEdit.Normal)
        if ok and txt:
            pathFolder = self.itemCurrent.getPath(withFileName = False, withFolderName=True)
            UCI.instance().addLibraryRepo( pathFolder=pathFolder, libraryName = txt, mainLibraries=True)

    def addLibrary(self):
        """
        Add one library
        """
        txt, ok = QInputDialog.getText(self, "Library name", "Enter name:", QLineEdit.Normal)
        if ok and txt:
            pathFolder = self.itemCurrent.getPath(withFileName = False, withFolderName=True)
            UCI.instance().addLibraryRepo( pathFolder=pathFolder, libraryName = txt)

    def checkSyntaxLibraries(self):
        """
        Check syntax of all libraries
        """
        RCI.instance().checkSyntaxLibraries()

    def moreCreateActions(self):
        """
        On more create qt actions
        """
        self.addLibrariesAction = QtHelper.createAction(self, "&Add Libraries", self.addLibraries, 
                                        icon = QIcon(":/libraries.png"), tip = 'Create a new set of library' )
        self.addLibraryAction = QtHelper.createAction(self, "&Add Library", self.addLibrary, 
                                        icon = QIcon(":/libraries.png"), tip = 'Create new library' )
        self.checkLibrariesAction = QtHelper.createAction(self, "&Check", self.checkSyntaxLibraries, 
                                        icon = QIcon(":/libraries-check.png"), tip = 'Check syntax of all libraries' )
        self.setAsDefaultAction = QtHelper.createAction(self, "&Set as default", self.setLibraryAsDefault, 
                                        icon = None, tip = 'Set library as default' )
        self.setAsGenericAction = QtHelper.createAction(self, "&Set as generic", self.setLibraryAsGeneric, 
                                        icon = None, tip = 'Set library as generic' )
                                        
    def moreDefaultActions(self):
        """
        Reimplemented from RemoteRepository
        """
        self.addLibrariesAction.setEnabled(False)
        self.addLibraryAction.setEnabled(False)
        self.checkLibrariesAction.setEnabled(False)
        self.setAsDefaultAction.setEnabled(False)
        self.setAsGenericAction.setEnabled(False)

    def onMorePopupMenu(self, itemType):
        """
        Reimplemented from RemoteRepository
        """
        if itemType == QTreeWidgetItem.UserType+10 : # root
            self.menu.addSeparator()
            self.menu.addAction( self.addLibrariesAction )
            self.menu.addAction( self.checkLibrariesAction )
        else:
            self.menu.addSeparator()
            self.menu.addAction( self.addLibraryAction )
            self.menu.addAction( self.setAsDefaultAction )
            self.menu.addAction( self.setAsGenericAction )

    def onMoreCurrentItemChanged(self, itemType):
        """
        Reimplemented from RemoteRepository
        """
        if itemType == QTreeWidgetItem.UserType+0: # file
            self.addLibraryAction.setEnabled(False)
            self.checkLibrariesAction.setEnabled(False)
            self.addLibrariesAction.setEnabled(False)
            self.setAsDefaultAction.setEnabled(False)
            self.setAsGenericAction.setEnabled(False)
        elif itemType == QTreeWidgetItem.UserType+1: # dir
            if self.itemCurrent.parent().isRoot:
                self.addLibraryAction.setEnabled(True)
                self.setAsDefaultAction.setEnabled(True)
                self.setAsGenericAction.setEnabled(True)
            else:
                self.addLibraryAction.setEnabled(False)
                self.setAsDefaultAction.setEnabled(False)
                self.setAsGenericAction.setEnabled(False)
            self.checkLibrariesAction.setEnabled(False)
            self.addLibrariesAction.setEnabled(False)
        elif itemType == QTreeWidgetItem.UserType+10 : #root
            self.addLibraryAction.setEnabled(False)
            self.addLibrariesAction.setEnabled(True)
            self.setAsDefaultAction.setEnabled(False)
            self.setAsGenericAction.setEnabled(False)
            self.checkLibrariesAction.setEnabled(True)
        else:
            self.addLibraryAction.setEnabled(False)
            self.checkLibrariesAction.setEnabled(False)
            self.addLibrariesAction.setEnabled(False)
            self.setAsDefaultAction.setEnabled(False)
            self.setAsGenericAction.setEnabled(False)

    def setLibraryAsDefault(self):
        """
        Set library as default
        """
        pathFolder = self.itemCurrent.getPath(withFileName = False, 
                                              withFolderName=True)
        RCI.instance().setDefaultLibrary(packageName=pathFolder)

    def setLibraryAsGeneric(self):
        """
        Set library as default
        """
        pathFolder = self.itemCurrent.getPath(withFileName = False, 
                                              withFolderName=True)
        RCI.instance().setGenericLibrary(packageName=pathFolder)
        
    def moveRemoteFile(self, currentName, currentPath, currentExtension, newPath):
        """
        Reimplemented from RemoteRepository
        Move remote file
        """
        # UCI.instance().moveFileRepo( repo=UCI.REPO_LIBRARIES, mainPath=currentPath, 
                                     # FileName=currentName, extFile=currentExtension, newPath=newPath)
        RCI.instance().moveFileLibraries(filePath=currentPath, fileName=currentName, 
                                         fileExt=currentExtension, 
                                         newPath=newPath)
                                     
    def moveRemoteFolder(self, currentName, currentPath, newPath):
        """
        Reimplemented from RemoteRepository
        Move remote folder
        """
        # UCI.instance().moveFolderRepo( repo=UCI.REPO_LIBRARIES, mainPath=currentPath, 
                                       # FolderName=currentName, newPath=newPath)
        RCI.instance().moveFolderLibraries(folderPath=currentPath, 
                                           folderName=currentName, 
                                           newPath=newPath)
                                       
    def openRemoteFile (self, pathFile):
        """
        Reimplemented from RemoteRepository
        Open remote file

        @param pathFile: 
        @type pathFile:
        """
        # UCI.instance().openFileRepo( repo=UCI.REPO_LIBRARIES, pathFile = pathFile)
        RCI.instance().openFileLibraries(filePath=pathFile)
        
    def deleteAllFolders (self, pathFolder):
        """
        Reimplemented from RemoteRepository
        Delete all folders
        
        @param pathFolder: 
        @type pathFolder:
        """
        # UCI.instance().delDirAllRepo( repo=UCI.REPO_LIBRARIES, pathFolder=pathFolder)
        RCI.instance().removeFoldersLibraries(folderPath=pathFolder)
        
    def deleteFile (self, pathFile):
        """
        Reimplemented from RemoteRepository
        Delete file

        @param pathFile: 
        @type pathFile:
        """
        # UCI.instance().delFileRepo(repo=UCI.REPO_LIBRARIES, pathFile=pathFile)
        RCI.instance().removeFileLibraries(filePath=pathFile)
        
    def deleteFolder (self, pathFolder):
        """
        Reimplemented from RemoteRepository
        Delete folder
        
        @param pathFolder: 
        @type pathFolder:
        """
        # UCI.instance().delDirRepo( repo=UCI.REPO_LIBRARIES, pathFolder=pathFolder)
        RCI.instance().removeFolderLibraries(folderPath=pathFolder)
        
    def addFolder (self, pathFolder, folderName):
        """
        Reimplemented from RemoteRepository
        Add folder
        
        @param pathFolder: 
        @type pathFolder:

        @param folderName: 
        @type folderName:
        """
        # UCI.instance().addDirRepo( repo=UCI.REPO_LIBRARIES, pathFolder=pathFolder, folderName = folderName)
        RCI.instance().addFolderLibraries(folderPath=pathFolder, 
                                          folderName = folderName)
        
    def refresh(self):
        """
        Reimplemented from RemoteRepository
        Refresh
        """
        # UCI.instance().refreshRepo(repo=UCI.REPO_LIBRARIES)
        RCI.instance().listingLibraries()
        
    def renameFile (self, mainPath, oldFileName, newFileName, extFile):
        """
        Reimplemented from RemoteRepository
        Rename file

        @param mainPath: 
        @type mainPath:

        @param oldFileName: 
        @type oldFileName:

        @param newFileName: 
        @type newFileName:

        @param extFile: 
        @type extFile:
        """
        # UCI.instance().renameFileRepo(repo=UCI.REPO_LIBRARIES, mainPath=mainPath, 
                                        # oldFileName=oldFileName, newFileName= newFileName, extFile=extFile)
        RCI.instance().renameFileLibraries( filePath=mainPath, 
                                            fileName=oldFileName, 
                                            fileExt=extFile, 
                                            newName=newFileName)
                                             
    def renameFolder (self, mainPath, oldFolderName, newFolderName):
        """
        Reimplemented from RemoteRepository
        Rename folder

        @param mainPath: 
        @type mainPath:

        @param oldFolderName: 
        @type oldFolderName:

        @param newFolderName: 
        @type newFolderName:
        """
        # UCI.instance().renameDirRepo(repo=UCI.REPO_LIBRARIES, mainPath=mainPath, 
                                     # oldFolder=oldFolderName, newFolder=newFolderName)
        RCI.instance().renameFolderLibraries(folderPath=mainPath, 
                                             folderName = oldFolderName, 
                                             newName=newFolderName)
                                         
    def duplicateFile (self, mainPath, oldFileName, newFileName, extFile, newPath=''):
        """
        Reimplemented from RemoteRepository
        Duplicate file

        @param mainPath: 
        @type mainPath:

        @param oldFileName: 
        @type oldFileName:

        @param newFileName: 
        @type newFileName:

        @param extFile: 
        @type extFile:
        """
        # UCI.instance().duplicateFileRepo(repo=UCI.REPO_LIBRARIES, mainPath=mainPath, oldFileName=oldFileName, 
                                        # newFileName=newFileName, extFile=extFile, newPath=newPath)
        RCI.instance().duplicateFileLibraries(filePath=mainPath,
                                               fileName=oldFileName, 
                                               fileExt=extFile, 
                                               newPath=newPath, 
                                               newName=newFileName)
        
    def duplicateFolder (self, mainPath, oldFolderName, newFolderName, newPath=''):
        """
        Reimplemented from RemoteRepository
        Duplicate folder

        @param mainPath: 
        @type mainPath:

        @param oldFolderName: 
        @type oldFolderName:

        @param newFolderName: 
        @type newFolderName:
        """
        # UCI.instance().duplicateDirRepo(repo=UCI.REPO_LIBRARIES, mainPath=mainPath, oldFolderName=oldFolderName,
                                        # newFolderName=newFolderName, newPath=newPath)
        RCI.instance().duplicateFolderLibraries( folderPath=mainPath, 
                                                folderName = oldFolderName, 
                                                newPath=newPath,
                                                newName=newFolderName)