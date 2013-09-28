combina-0.4.2
=============

An upgrade to the original combina password and rainbow table generator.
So, after a way too long of a time we have updated combina!
Combina is a password generator and a rainbow table generator created by Danilo Cicerone at 2006. 
The program is written in C and since it is so efficient and effective (and written under the GNU license agreement) 
we had to make some improvements since it was deprecated. 
Thanks to Ohad Gopher (Hacking Defined Experts 41) who made most of the changes to the code making it do more awesome tricks.

Change Log:
-----------
    Combina can now generate NTLM hashes
    Combina can now generate SHA256 hashes
    Combina can now generate SHA384 hashes
    Combina can now generate SHA512 hashes
    
We are still open to more suggestions but since this program was very close to perfection when it came out, 
we didn’t see anything else which needed to be added. You should verify the following libraries before trying to compile the project:
    sudo apt-get install libargtable2-dev libssl-dev

GPLv3:
------
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
