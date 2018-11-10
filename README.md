Interrogate
===========

Interrogate is a proof-of-concept tool for identification of cryptographic keys
in binary material (regardless of target operating system), first and foremost
for memory dump analysis and forensic usage. Able to identify AES, Serpent, 
Twofish and DER-encoded RSA keys as of version 0.0.4. 

The tool was written as a part of my Master’s Thesis at NTNU.


Key data
--------

 * Version: 0.0.4
 * License: GPL
 * Author: 	Carsten Maartmann-Moe (carsten@carmaa.com)
 * Twitter: @MaartmannMoe
 * Source: 	https://github.com/carmaa/interrogate


Requirements
------------

Interrogate requires:

 * Linux or Mac OS X


Installation
------------

Interrogate has no dependencies, installation consists of downloading and
compiling:

### Download and install

	git clone https://github.com/carmaa/interrogate.git
	cd interrogate
	make


Usage
-----

 1. Dump memory from the target machine
 2. Run Interrogate against the memory dump

For a more complete and up-to-date description, please run:

	./interrogate -h


Known bugs / caveats
--------------------

This is a Proof of Concept tool only. Don't expect too much.


Troubleshooting
---------------

Please see my master's thesis: https://brage.bibsys.no/xmlui/handle/11250/261742

And the related paper: https://dfrws.org/sites/default/files/session-files/paper-the_persistence_of_memory_-_forensic_identification_and_extraction_of_cryptographic_keys.pdf


Planned features
----------------

 * None
 
 
Development history
-------------------
 
 * 0.0.1 - First version
 * 0.0.2 - Added TwoFish and Serpent key search functionality
 * 0.0.3 - The version that was released with my Master's thesis
 * 0.0.4 - Small bug fixes in conjunction with DFRWS 2009
 
 
Disclaimer
----------
Do no evil with this tool. Also, I am a pentester, not a developer. So if you
see weird code that bugs your purity senses, drop me a note on howI can improve 
it. Or even better, fork my code, change it and issue a pull request.
