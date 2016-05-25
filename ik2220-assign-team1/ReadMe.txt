NOTE: 
-----
Before proceeding, make sure you have X11 forwarding configured and your X11client is running (Using X11 Forwarding on PuTTY before opening the session and start Xming). NFV instances' consoles will spawn itself once the makefile is executed.

To run our Application:
1.	Install DPKT before launching our unified application. This is the only dependency we have to run our application. We tried adding “ pip install dpkt and sudo apt-get install python-dpkt ” but with the VMs not able to connect to the internet we could not test this and removed it from the Makefile.
2.	Make file contains the command to run the topology and clean the environment. 
3.	Command to run the topology file is “sudo python topology.py” as in Makefile.

Description:
Our approach involves a custom file which connects Mininet and our NFV components which are individual entities deployed as middleboxes. As soon as the Mininet topology is initiated it starts all the NFV components as well as the POX. 
We have created a custom element in regards to IDS - httprequestinspector.cc and httprequestinspector.hh and using it in the IDS element. Also, we have our own code to connect the mininet and the Click elements.
Testing:
Through our automated test process, we have tested the application and the various tasks results are reported in the “results” folder. Once the application is launched, the results of Pings and packet traffic are printed on the respective component consoles that are spawned automatically. 
