install:
        sudo apt-get install python-dpkt
        sudo cp ../application/nfv/elements/* /home/click/click/elements/test/
        cd /home/click/click/;make elemlist;make install
app:
        sudo cp ../application/sdn/controller.py ../application/sdn/firewall.py /home/click/pox/tests/
        sudo mkdir -p /home/click/click/conf/alpha
        sudo cp ../application/nfv/IDS.click ../application/nfv/LB1.click ../application/nfv/LB2.click ../application/nfv/NAPT.click /home/click/click/conf/alpha
        sudo mkdir -p /home/click/mininet/custom/services/
        sudo cp ../application/test_servers/dns/* ../application/test_servers/http/* /home/click/mininet/custom/services/
        sudo python topology.py

clean:
        sudo mn -c
