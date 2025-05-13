from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def run_network():
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)
    
    info('*** Adding controller\n')
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
    h2 = net.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
    ser = net.addHost('ser', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
    ext = net.addHost('ext', ip='192.168.1.123/24', defaultRoute='via 192.168.1.1')
    
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')  # This will act as our router
    
    info('*** Creating links\n')
    # Internal network 1
    net.addLink(h1, s1, bw=15, delay='10ms')
    net.addLink(h2, s1, bw=15, delay='10ms')
    net.addLink(s1, s3, bw=15, delay='10ms')
    
    # Internal network 2
    net.addLink(ser, s2, bw=15, delay='10ms')
    net.addLink(s2, s3, bw=15, delay='10ms')
    
    # External network
    net.addLink(ext, s3, bw=15, delay='10ms')
    
    info('*** Starting network\n')
    net.start()
    
    # Configure router (s3) interfaces
    s3.cmd('ifconfig s3-eth0 10.0.1.1/24')
    s3.cmd('ifconfig s3-eth1 10.0.2.1/24')
    s3.cmd('ifconfig s3-eth2 192.168.1.1/24')
    
    # Set MAC addresses for router interfaces
    s3.cmd('ifconfig s3-eth0 hw ether 00:00:00:00:01:01')
    s3.cmd('ifconfig s3-eth1 hw ether 00:00:00:00:01:02')
    s3.cmd('ifconfig s3-eth2 hw ether 00:00:00:00:01:03')
    
    # Enable IP forwarding on the router
    s3.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    info('*** Running CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_network()
