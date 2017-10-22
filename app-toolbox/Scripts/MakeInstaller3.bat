:: -------------------------------------------------------------------
:: Copyright (c) 2010-2017 Denis Machard
:: This file is part of the extensive testing project
::
:: This library is free software; you can redistribute it and/or
:: modify it under the terms of the GNU Lesser General Public
:: License as published by the Free Software Foundation; either
:: version 2.1 of the License, or (at your option) any later version.
::
:: This library is distributed in the hope that it will be useful,
:: but WITHOUT ANY WARRANTY; without even the implied warranty of
:: MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
:: Lesser General Public License for more details.
::
:: You should have received a copy of the GNU Lesser General Public
:: License along with this library; if not, write to the Free Software
:: Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
:: MA 02110-1301 USA
:: -------------------------------------------------------------------

@echo off

set Project=%~dp0..\
set Output=E:\My Lab\01 ExtensiveTesting\02 - Output\

set PythonPath=C:\Python34
set Python=%PythonPath%\python.exe
set PyQtPath=Lib\site-packages\PyQt4\

:: convert xml translations files
%PythonPath%\%PyQtPath%\lrelease.exe "%Project%\Translations\us_US.ts"
%PythonPath%\%PyQtPath%\lrelease.exe "%Project%\Translations\fr_FR.ts"

:: build translations resources
echo Building translations resources...
%PythonPath%\%PyQtPath%\pyrcc4.exe -py3 -o "%Project%\Translations\Translations.py" "%Project%\Translations\__resources.qrc"

:: build images resources
echo Building images resources...
%PythonPath%\Lib\site-packages\PyQt4\pyrcc4.exe -py3 -o "%Project%\Resources\Resources.py" "%Project%\Resources\__resources.qrc"

:: build the project
cd "%Project%"
%Python% "%Project%\ConfigureExe.py"
%Python% "%Project%\BuildWin.py" py2exe

:: create installer
"%Python%" "%Project%\BuildWinInstaller.py" "%Output%\"

pause