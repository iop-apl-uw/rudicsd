# Copyright (C) 2007, 2008, 2010, 2014 Geoff Shilling, Jason Gobat
# Copyright (C) 2006, 2007 Dana Swift
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

SHELL=/bin/csh
C++FLAGS= -x c++ -Wall 
CLIBS=-lutil 
C++LIBS=-lstdc++

all:    rudicsd

rudicsd: rudicsd.o
	gcc  -g -o rudicsd rudicsd.o $(CLIBS) $(C++LIBS) 

rudicsd.o: rudicsd.cpp
	gcc -g -c -o rudicsd.o $(C++FLAGS) rudicsd.cpp

install:
	cp rudicsd /usr/local/bin

clean:
	-rm rudicsd.o rudicsd
